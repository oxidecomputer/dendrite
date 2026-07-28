// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Create `tfport`s on the host that represent `dpd` links.
//!
//! `tfportd` and `dpd` share responsibility for maintaining the tfport devices.
//! `dpd` instantiates tofino links based on a config file describing the
//! backplane and admin input describing the links on the front plane.  Each
//! link is assigned a MAC address by dpd, derived by combining the link ID and
//! a per-sidecar value.  For each port configured at `dpd`, `tfportd`
//! instantiates a `tfport` dladm link and instructs illumos to assign it a
//! link-local IPv6 address.  When that address has been assigned, `tfportd`
//! notifies `dpd` to push that address into the tofino's p4 tables.
//!
//! `tfportd` regularly polls `dpd` for the population of configured ports and
//! the addresses it knows about.  If `tfportd` finds a discrepancy with the set
//! of `tfport` devices it maintains, it takes corrective action.
//!
//! In addition to maintaining the population of `tfport` links, this daemon
//! also montors the `tfpkt` source for packets arriving tagged with Sidecar
//! headers.  Those headers include a bit of extra information, added by the
//! Sidecar P4 program, such as the ASIC ID (a Tofino-level identifier for the
//! link); or why it was forwarded to the host (such as for NDP resolution).
//! This allows us to use the illumos host OS address resolution mechanisms,
//! such as the NDP daemon. The P4 program forwards packets that need
//! resolution; illumos resolves them and sends them back when that's complete.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use dpd_client::types;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;

use crate::Global;
use crate::poll_interval;
use crate::tfport;
use common::network::MacAddr;

/// Information about a single link in `dpd`, and its associated `tfport` if it
/// exists.
pub struct LinkInfo {
    /// The name of the link.
    pub name: String,
    /// The switch port ID for this link.
    pub port_id: types::PortId,
    /// The link ID for this link.
    pub link_id: types::LinkId,
    /// The low-level Tofino ID used to refer to this link.
    pub asic_id: u16,
    /// The MAC address for the link.
    pub mac: MacAddr,
    /// Is this link configured to support IPv6?
    pub ipv6_enabled: bool,
    /// Every IPv6 link-local address resident on the link in dpd, along
    /// with the owners that have claimed it.
    pub dpd_link_locals: Vec<types::Ipv6OwnedEntry>,

    /// The name of the `tfport` device, if it exists.
    pub tfport: Option<String>,
    /// The index of the `tfport` interface, if it exists.
    pub tfport_ifindex: Option<u32>,
    /// The IPv6 link-local address of the tfport in illumos, if it exists.
    pub tfport_link_local: Option<Ipv6Addr>,
}

impl fmt::Display for LinkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&types::TfportData> for LinkInfo {
    fn from(t: &types::TfportData) -> Self {
        LinkInfo {
            name: t.to_string(),
            port_id: t.port_id.clone(),
            link_id: t.link_id,
            asic_id: t.asic_id,
            mac: t.mac.clone().into(),
            ipv6_enabled: t.ipv6_enabled,
            dpd_link_locals: t.link_locals.clone(),
            tfport: None,
            tfport_ifindex: None,
            tfport_link_local: None,
        }
    }
}

/// The set of all links on the system, and their `tfports`.
type LinkMap = BTreeMap<String, LinkInfo>;

// Return the name for a `tfport` device, based on the link it represents.
fn tfport_name(link: &types::TfportData) -> String {
    format!("tfport{}_{}", link.port_id, *link.link_id)
}

// Fetch the set of ports configured by dpd and update our internal LinkMap
async fn dpd_port_update(g: &Global, links: &mut LinkMap) -> Result<()> {
    // Fetch all links that `dpd` knows about.
    let dpd_data = g
        .client
        .tfport_data()
        .await
        .context("failed to list all links")?
        .into_inner()
        .into_iter();

    let mut current_links: BTreeSet<String> = links.keys().cloned().collect();

    // Iterate over the dpd list, updating our LinkInfo for each port with the
    // current illumos state.  Any dpd ports that don't already have LinkInfo
    // entries will have them created at this point.
    for entry in dpd_data {
        let expected_tfport = tfport_name(&entry);
        let _ = current_links.remove(&expected_tfport);
        let link =
            links.entry(expected_tfport.clone()).or_insert((&entry).into());
        let entry_mac = entry.mac.into();
        link.dpd_link_locals = entry.link_locals;

        // Check to see if the state in dpd matches our in-core state.
        // Neither of these should change, so it's definitely worth logging.
        // Any change here should cause a mismatch when looking at the existing
        // tfports.
        if link.mac != entry_mac {
            warn!(
                g.log, "tfport changed mac addresses";
                "tfport" => &expected_tfport,
                "mac" => entry_mac.to_string(),
                "stale_mac" => link.mac.to_string()
            );
            link.mac = entry_mac;
        }
        if link.asic_id != entry.asic_id {
            warn!(
                g.log, "tfport changed asic IDs";
                "tfport" => &expected_tfport,
                "asic_id" => entry.asic_id,
                "stale_asic_id" => link.asic_id
            );
            link.asic_id = entry.asic_id;
        }
    }

    // Stop tracking any ports that no longer exist
    while let Some(link) = current_links.pop_first() {
        info!(g.log, "{link} no longer exists at dpd");
        let _ = links.remove(&link);
    }

    Ok(())
}

// Fetch the tfports configured in illumos and update our internal LinkMap.
// Returns a list of the tfports that no longer have corresponding ports in dpd.
async fn illumos_port_update(
    g: &Global,
    links: &mut LinkMap,
) -> Result<Vec<String>> {
    // Fetch the list of tfports configured in illumos
    let mut illumos_data = tfport::tfport_list().await?;

    for (tfport, link) in links {
        match illumos_data.get(tfport) {
            Some(data) => {
                // If the local port matches the dpd-configured port (as we
                // generally expect it will), update the LinkInfo struct
                // with the illumos state.  If the port doesn't match, we
                // leave the entry in the illumos_data to get cleaned up in
                // the next step as an orphan.
                if link.asic_id == data.port && link.mac == data.mac {
                    let data = illumos_data
                        .remove(tfport)
                        .expect("existence already checked");
                    link.tfport = Some(tfport.to_string());
                    link.tfport_ifindex = data.ifindex;
                    link.tfport_link_local = data.link_local;
                    continue;
                } else {
                    info!(
                        g.log, "tfport found with stale data";
                        "tfport" => tfport,
                        "mac" => link.mac.to_string(),
                        "stale_mac" => data.mac.to_string(),
                        "asic_id" => link.asic_id,
                        "stale_asic_id" => data.port
                    );
                }
            }
            None => {
                if link.tfport.is_some() {
                    info!(g.log, "tfport disappeared"; "tfport" => tfport);
                }
            }
        }

        // If we get here, it's because the current tfport (if any) doesn't
        // match the dpd state.  Clearing these fields will cause the
        // correct tfport to get created.
        link.tfport = None;
        link.tfport_ifindex = None;
        link.tfport_link_local = None;
    }

    // Any ports left in this list either had no correponding dpd info, or had
    // stale dpd info.  Either way, we return them as "orphans" to be cleaned up.
    Ok(illumos_data.keys().cloned().collect())
}

/// The operations needed to bring our claims on a link's dpd-resident
/// link-local addresses in line with the tfport state in illumos.
///
/// A plan only ever touches claims held by our own owner tag; link-local
/// addresses claimed exclusively by other owners are never released, and an
/// address we co-own with another owner only has our claim released.
#[derive(Debug, Default, PartialEq, Eq)]
struct LinkLocalPlan {
    /// Stale claims of ours to release.
    release: Vec<Ipv6Addr>,
    /// The illumos link-local address to claim, if we don't already hold a
    /// claim on it.
    claim: Option<Ipv6Addr>,
}

impl LinkLocalPlan {
    fn is_empty(&self) -> bool {
        self.release.is_empty() && self.claim.is_none()
    }
}

// Compute the operations needed to make our link-local claims in dpd match
// the address set on the local tfport by illumos.
//
// The plan considers only the addresses we own (i.e., those whose owner set
// contains our tag):
//
//   1. Any address we own that doesn't match the illumos link-local address
//      is stale, and our claim on it is released (*).
//
//   2. If we don't own the illumos link-local address, we claim it.
//
// Addresses owned solely by other clients are invisible to this process:
// they are theirs to manage, and planning around them must not prevent this
// function from reaching a fixed point (an empty plan) once our own claims
// match the illumos state.
//
// (*) It would be very weird for the two sides to have different link-local
//     addresses, since they are derived from the mac address.  This should only
//     happen if the mac address changes which, as noted in dpd_port_update(),
//     would also be very weird.
fn plan_link_local_sync(
    owner: &types::Tag,
    dpd_link_locals: &[types::Ipv6OwnedEntry],
    tfport_link_local: Option<Ipv6Addr>,
) -> LinkLocalPlan {
    let owned: BTreeSet<Ipv6Addr> = dpd_link_locals
        .iter()
        .filter(|entry| entry.owners.contains(owner))
        .map(|entry| entry.addr)
        .collect();

    LinkLocalPlan {
        release: owned
            .iter()
            .copied()
            .filter(|addr| Some(*addr) != tfport_link_local)
            .collect(),
        claim: tfport_link_local.filter(|addr| !owned.contains(addr)),
    }
}

// Make sure that our claims on link-local addresses configured in dpd match
// the address set on the local tfport by illumos.  See
// plan_link_local_sync() for the reconciliation rules.
async fn ensure_address_match(g: &Global, link: &LinkInfo) -> Result<()> {
    let plan = plan_link_local_sync(
        &g.owner,
        &link.dpd_link_locals,
        link.tfport_link_local,
    );

    for addr in &plan.release {
        warn!(g.log, "releasing stale dpd address: {addr}");
        match g
            .client
            .link_ipv6_release(&link.port_id, &link.link_id, addr, &g.owner)
            .await
        {
            Ok(_) => {}
            // Our snapshot of the dpd state may be stale: a NOT_FOUND means
            // the claim is already gone.
            Err(e) if e.status() == Some(http::StatusCode::NOT_FOUND) => {
                info!(
                    g.log,
                    "claim on link-local {addr} on {}/{} already released",
                    link.port_id,
                    link.link_id
                );
            }
            Err(e) => {
                return Err(e).context("releasing stale link-local address");
            }
        }
    }

    if let Some(addr) = plan.claim {
        info!(g.log, "claiming tfport address: {addr}");
        g.client
            .link_ipv6_claim(
                &link.port_id,
                &link.link_id,
                &addr,
                &types::AddressClaim { owner: g.owner.clone() },
            )
            .await
            .context("claiming link-local address")?;
    }

    Ok(())
}

pub async fn port_loop(g: Arc<Global>) {
    let mut link_map = LinkMap::new();
    while g.get_running() {
        // Fetch the latest link state from dpd and update our LinkMap
        if let Err(e) = dpd_port_update(&g, &mut link_map).await {
            error!(g.log, "{:?}", e);
        }

        // Fetch the latest tfport state from illumos, including the list of any
        // "orphaned" tfports that no longer have matching links in dpd.
        let orphans = match illumos_port_update(&g, &mut link_map).await {
            Ok(orphans) => orphans,
            Err(e) => {
                error!(g.log, "{:?}", e);
                Vec::new()
            }
        };

        // Clean up any orphaned tfports
        for tfport in orphans {
            if let Err(e) = tfport::tfport_delete(&g, &tfport).await {
                error!(
                    g.log,
                    "failed to clean up stale tfport: {e:?}";
                    "tfport" => tfport
                );
            }
        }

        let mut tfport_to_asic = BTreeMap::new();
        let mut asic_to_ifindex = BTreeMap::new();
        // Iterate over all of the links and ensure that the local tfport state
        // is in sync with the dpd state.  While we're at it, update the maps
        // used elsewhere in the daemon.
        for (tfport, link) in &link_map {
            tfport_to_asic.insert(tfport.to_string(), link.asic_id);
            if let Some(ifindex) = link.tfport_ifindex {
                asic_to_ifindex.insert(link.asic_id, ifindex);
            }

            if let Err(e) = tfport::tfport_ensure(&g, tfport, link).await {
                error!(
                    g.log,
                    "tfport_ensure() failed: {e:?}";
                    "tfport" => tfport
                );
            }

            if let Err(e) = ensure_address_match(&g, link).await {
                error!(
                    g.log,
                    "ensure_address_match() failed: {e:?}";
                    "tfport" => tfport
                );
            }
        }
        *g.tfport_to_asic.lock().unwrap() = tfport_to_asic;
        *g.asic_to_ifindex.lock().unwrap() = asic_to_ifindex;

        tokio::time::sleep(poll_interval()).await;
    }

    debug!(g.log, "port loop exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(name: &str) -> types::Tag {
        types::Tag::try_from(name).unwrap()
    }

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn entry(a: &str, owners: &[&types::Tag]) -> types::Ipv6OwnedEntry {
        types::Ipv6OwnedEntry {
            addr: addr(a),
            owners: owners.iter().map(|t| (*t).clone()).collect(),
        }
    }

    // Model dpd's response to a plan: releasing removes our claim (and the
    // address once its owner set is empty), claiming adds one.
    fn apply_plan(
        owner: &types::Tag,
        dpd_link_locals: &mut Vec<types::Ipv6OwnedEntry>,
        plan: &LinkLocalPlan,
    ) {
        for release in &plan.release {
            if let Some(pos) =
                dpd_link_locals.iter().position(|e| e.addr == *release)
            {
                dpd_link_locals[pos].owners.retain(|t| t != owner);
                if dpd_link_locals[pos].owners.is_empty() {
                    dpd_link_locals.remove(pos);
                }
            }
        }
        if let Some(claim) = plan.claim {
            match dpd_link_locals.iter_mut().find(|e| e.addr == claim) {
                Some(e) => {
                    if !e.owners.contains(owner) {
                        e.owners.push(owner.clone());
                    }
                }
                None => dpd_link_locals.push(types::Ipv6OwnedEntry {
                    addr: claim,
                    owners: vec![owner.clone()],
                }),
            }
        }
    }

    // Assert that after applying `plan`, replanning against the resulting
    // dpd state produces an empty plan (i.e., reconciliation converges
    // rather than looping forever).
    fn assert_fixed_point(
        owner: &types::Tag,
        mut dpd_link_locals: Vec<types::Ipv6OwnedEntry>,
        tfport_link_local: Option<Ipv6Addr>,
        plan: &LinkLocalPlan,
    ) {
        apply_plan(owner, &mut dpd_link_locals, plan);
        let replan =
            plan_link_local_sync(owner, &dpd_link_locals, tfport_link_local);
        assert!(
            replan.is_empty(),
            "reconciliation did not converge: second pass still \
             plans work: {replan:?}"
        );
    }

    // The bug this planner replaces: a foreign owner's link-local that
    // sorts before ours must not be mistaken for our own claim.  The old
    // code took the first link-local on the link regardless of owner,
    // tried (and failed) to release it, re-claimed its own address, and
    // repeated that forever.  With everything already in sync, the plan
    // must be empty.
    #[test]
    fn foreign_link_local_sorting_first_reaches_fixed_point() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let ours = addr("fe80::2");
        let dpd = vec![entry("fe80::1", &[&them]), entry("fe80::2", &[&us])];

        let plan = plan_link_local_sync(&us, &dpd, Some(ours));
        assert!(
            plan.is_empty(),
            "in-sync state must plan no work, got {plan:?}"
        );
        assert_fixed_point(&us, dpd, Some(ours), &plan);
    }

    // A stale claim of ours is released and the expected address claimed.
    #[test]
    fn stale_owned_address_is_replaced() {
        let us = tag("tfportd");
        let expected = addr("fe80::2");
        let dpd = vec![entry("fe80::1", &[&us])];

        let plan = plan_link_local_sync(&us, &dpd, Some(expected));
        assert_eq!(plan.release, vec![addr("fe80::1")]);
        assert_eq!(plan.claim, Some(expected));
        assert_fixed_point(&us, dpd, Some(expected), &plan);
    }

    // A foreign address is left alone; we just claim our own.
    #[test]
    fn foreign_address_is_not_released_when_claiming() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let expected = addr("fe80::2");
        let dpd = vec![entry("fe80::1", &[&them])];

        let plan = plan_link_local_sync(&us, &dpd, Some(expected));
        assert!(plan.release.is_empty(), "foreign claim must not be released");
        assert_eq!(plan.claim, Some(expected));
        assert_fixed_point(&us, dpd, Some(expected), &plan);
    }

    // With no illumos link-local, our claim is released; a foreign claim
    // is not.
    #[test]
    fn owned_address_released_when_tfport_has_none() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let dpd = vec![entry("fe80::1", &[&them]), entry("fe80::2", &[&us])];

        let plan = plan_link_local_sync(&us, &dpd, None);
        assert_eq!(plan.release, vec![addr("fe80::2")]);
        assert_eq!(plan.claim, None);
        assert_fixed_point(&us, dpd, None, &plan);
    }

    // A link with only foreign claims and no illumos address needs no work.
    #[test]
    fn foreign_only_link_is_untouched() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let dpd = vec![entry("fe80::1", &[&them])];

        let plan = plan_link_local_sync(&us, &dpd, None);
        assert!(plan.is_empty(), "foreign-only link must plan no work");
    }

    // An address we co-own with another client counts as ours: nothing to
    // do when it matches illumos.
    #[test]
    fn co_owned_matching_address_is_in_sync() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let expected = addr("fe80::1");
        let dpd = vec![entry("fe80::1", &[&them, &us])];

        let plan = plan_link_local_sync(&us, &dpd, Some(expected));
        assert!(plan.is_empty(), "co-owned in-sync address needs no work");
    }

    // Releasing a stale co-owned address only drops our claim; the other
    // owner keeps the address, and reconciliation still converges.
    #[test]
    fn stale_co_owned_address_release_converges() {
        let us = tag("tfportd");
        let them = tag("ddm");
        let expected = addr("fe80::2");
        let dpd = vec![entry("fe80::1", &[&them, &us])];

        let plan = plan_link_local_sync(&us, &dpd, Some(expected));
        assert_eq!(plan.release, vec![addr("fe80::1")]);
        assert_eq!(plan.claim, Some(expected));

        let mut after = dpd.clone();
        apply_plan(&us, &mut after, &plan);
        assert_eq!(
            after,
            vec![entry("fe80::1", &[&them]), entry("fe80::2", &[&us])],
            "the other owner must retain its claim"
        );
        assert_fixed_point(&us, dpd, Some(expected), &plan);
    }

    // If we somehow hold claims on several link-locals, all the stale ones
    // are released in one pass and reconciliation converges.
    #[test]
    fn multiple_owned_addresses_converge() {
        let us = tag("tfportd");
        let expected = addr("fe80::2");
        let dpd = vec![
            entry("fe80::1", &[&us]),
            entry("fe80::2", &[&us]),
            entry("fe80::3", &[&us]),
        ];

        let plan = plan_link_local_sync(&us, &dpd, Some(expected));
        assert_eq!(plan.release, vec![addr("fe80::1"), addr("fe80::3")]);
        assert_eq!(plan.claim, None);
        assert_fixed_point(&us, dpd, Some(expected), &plan);
    }
}
