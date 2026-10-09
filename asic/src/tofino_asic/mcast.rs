// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashMap;

use slog::{debug, error, info};

use crate::tofino_asic::bf_wrapper::*;
use crate::tofino_asic::genpd::*;
use crate::tofino_asic::{BF_MC_LAG_ARRAY_SIZE, BF_MC_PORT_ARRAY_SIZE};
use crate::tofino_asic::{CheckError, Handle};

use aal::{AsicError, AsicResult};

pub struct DomainState {
    id: u16,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
    /// Ports whose node is associated with the `mgrp_hdl`, i.e. a port still
    /// available for replication.
    ports: HashMap<u16, MulticastState>,
    /// Nodes that are dissociated (or were never associated) but failed to
    /// destroy. `destroy_detached_nodes` retries them.
    detached_nodes: Vec<bf_mc_node_hdl_t>,
}

/*
 * Tracks the port population of each multicast domain
 */
struct MulticastState {
    node_hdl: bf_mc_node_hdl_t,
    portmap: Vec<u8>,
    lagmap: Vec<u8>,
}

fn port_to_pipe(port: u16) -> u16 {
    ((port) >> 7) & 3
}
fn port_to_local_port(port: u16) -> u16 {
    port & 0x7F
}
fn port_to_bit(port: u16) -> u16 {
    72 * port_to_pipe(port) + port_to_local_port(port)
}

fn bit_set(bitmap: &mut [u8], port: u16) {
    let idx = port_to_bit(port) as usize;
    let byte = idx / 8;
    let bit = idx % 8;

    bitmap[byte] |= 1 << bit;
}

pub fn create_session() -> AsicResult<u32> {
    let mut mcast_hdl = 0u32;
    unsafe { bf_mc_create_session(&mut mcast_hdl) }
        .check_error("creating multicast session")?;
    Ok(mcast_hdl)
}

fn mgrp_create(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    domain: u16,
) -> AsicResult<u32> {
    let mut mgrp_hdl = 0u32;
    unsafe {
        bf_mc_mgrp_create(mcast_hdl, dev_id, domain, &mut mgrp_hdl)
            .check_error("creating multicast group")?;
    }
    Ok(mgrp_hdl)
}

fn mgrp_destroy(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
) -> AsicResult<()> {
    unsafe {
        bf_mc_mgrp_destroy(mcast_hdl, dev_id, mgrp_hdl)
            .check_error("destroying multicast group")?;
    }
    Ok(())
}

fn mgrp_get_count(
    mcast_hdl: &Handle,
    dev_id: bf_dev_id_t,
    mut count: u32,
) -> AsicResult<usize> {
    unsafe {
        bf_mc_mgrp_get_count(mcast_hdl.bf_get().mcast_hdl, dev_id, &mut count)
            .check_error("getting total count of multicast groups")?;
    }

    Ok(count as usize)
}

fn associate_node(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
    node_hdl: bf_mc_node_hdl_t,
    exclusion_id: u16,
) -> AsicResult<()> {
    unsafe {
        bf_mc_associate_node(
            mcast_hdl,
            dev_id,
            mgrp_hdl,
            node_hdl,
            exclusion_id != 0,
            exclusion_id,
        )
        .check_error("associating multicast node")?;
    }
    Ok(())
}

fn dissociate_node(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
    node_hdl: bf_mc_node_hdl_t,
) -> AsicResult<()> {
    let res = unsafe {
        bf_mc_dissociate_node(mcast_hdl, dev_id, mgrp_hdl, node_hdl)
            .check_error("dissociating multicast node from group")
    };

    if let Err(AsicError::Exists(_)) = &res
        && !node_is_associated(mcast_hdl, dev_id, node_hdl)?
    {
        return Ok(());
    }
    res
}

fn node_is_associated(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    node_hdl: bf_mc_node_hdl_t,
) -> AsicResult<bool> {
    let mut is_associated = false;
    unsafe {
        bf_mc_node_get_association(
            mcast_hdl,
            dev_id,
            node_hdl,
            &mut is_associated,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .check_error("getting multicast node association")?;
    }
    Ok(is_associated)
}

fn node_create(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    repl_id: u16,
    portmap: &mut [u8],
    lagmap: &mut [u8],
) -> AsicResult<u32> {
    let mut node_hdl = 0u32;

    unsafe {
        bf_mc_node_create(
            mcast_hdl,
            dev_id,
            repl_id,
            portmap.as_mut_ptr(),
            lagmap.as_mut_ptr(),
            &mut node_hdl,
        )
        .check_error("creating multicast node")?;
    }
    Ok(node_hdl)
}

fn node_destroy(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    node_hdl: bf_mc_node_hdl_t,
) -> AsicResult<()> {
    unsafe {
        bf_mc_node_destroy(mcast_hdl, dev_id, node_hdl)
            .check_error("destroying multicast node")?;
    }
    Ok(())
}

/// Dissociate the `node_hdl` from `mgrp_hdl` and destroy it.
///
/// A dissociation error can leave the node attached or detached. The caller
/// retains its handle for retry or re-association.
///
/// Once the node is detached, a failed destroy on the underlying ASIC retains
/// the handle in `detached_nodes` and still returns a non-error result because
/// the port no longer replicates to subscribers.
fn detach_node(
    log: &slog::Logger,
    bf: &BfCommon,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
    node_hdl: bf_mc_node_hdl_t,
    detached_nodes: &mut Vec<bf_mc_node_hdl_t>,
) -> AsicResult<()> {
    match dissociate_node(bf.mcast_hdl, bf.dev_id, mgrp_hdl, node_hdl) {
        Ok(()) | Err(AsicError::Missing(_)) => {}
        Err(e) => return Err(e),
    }

    if let Err(e) = node_destroy(bf.mcast_hdl, bf.dev_id, node_hdl) {
        error!(
            log,
            "multicast node {:#x} detached but not destroyed: {:?}",
            node_hdl,
            e
        );
        detached_nodes.push(node_hdl);
    }
    Ok(())
}

/// Retry destroying the handles in `detached_nodes` within the domain state,
/// keeping any that remain in a failing state, and returning the first failure.
fn destroy_detached_nodes(
    log: &slog::Logger,
    bf: &BfCommon,
    domain: &mut DomainState,
) -> Option<AsicError> {
    let mut first_error = None;
    for node_hdl in std::mem::take(&mut domain.detached_nodes) {
        if let Err(e) = node_destroy(bf.mcast_hdl, bf.dev_id, node_hdl) {
            error!(
                log,
                "destroying detached multicast node {:#x} in domain {}: {:?}",
                node_hdl,
                domain.id,
                e
            );
            first_error.get_or_insert(e);
            domain.detached_nodes.push(node_hdl);
        }
    }
    first_error
}

fn set_max_node_threshold(
    mcast_hdl: bf_mc_session_hdl_t,
    dev_id: bf_dev_id_t,
    node_count: i32,
    node_port_lag_count: i32,
) -> AsicResult<()> {
    unsafe {
        bf_mc_set_max_node_threshold(
            mcast_hdl,
            dev_id,
            node_count,
            node_port_lag_count,
        )
        .check_error("setting max node threshold")?;
    }

    Ok(())
}

/// All multicast domains.
pub fn domains(hdl: &Handle) -> Vec<u16> {
    let mut list = Vec::new();
    let domains = hdl.domains.lock().unwrap();

    for domain in (*domains).keys() {
        list.push(*domain)
    }

    list.sort_unstable();
    list
}

#[allow(dead_code)]
fn domain_ports(domain: &DomainState) -> Vec<u16> {
    let mut list = Vec::new();

    for port in domain.ports.keys() {
        list.push(*port)
    }

    list.sort_unstable();
    list
}

/// Get the number of ports in a multicast domain.
pub fn domain_port_count(hdl: &Handle, group_id: u16) -> AsicResult<usize> {
    let domains = hdl.domains.lock().unwrap();
    match domains.get(&group_id) {
        Some(d) => Ok(d.ports.len()),
        None => Err(AsicError::Missing("no such domain".to_string())),
    }
}

/// Add a port to a multicast domain.
pub fn domain_add_port(
    hdl: &Handle,
    group_id: u16,
    port: u16,
    rid: u16,
    level_1_excl_id: u16,
) -> AsicResult<()> {
    debug!(hdl.log, "adding port {} to multicast domain {}", port, group_id);

    let mut domains = hdl.domains.lock().unwrap();
    let domain = match domains.get_mut(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::Missing("no such domain".to_string())),
    }?;

    let bf = hdl.bf_get();
    if let Some(mc) = domain.ports.get(&port) {
        if node_is_associated(bf.mcast_hdl, bf.dev_id, mc.node_hdl)? {
            return Err(AsicError::Exists(format!(
                "port {port} already in multicast domain {group_id}"
            )));
        }

        return associate_node(
            bf.mcast_hdl,
            bf.dev_id,
            domain.mgrp_hdl,
            mc.node_hdl,
            level_1_excl_id,
        );
    }

    destroy_detached_nodes(&hdl.log, &bf, domain);

    let mut mc = MulticastState {
        node_hdl: 0,
        portmap: vec![0u8; BF_MC_PORT_ARRAY_SIZE],
        lagmap: vec![0u8; BF_MC_LAG_ARRAY_SIZE],
    };

    bit_set(&mut mc.portmap, port);
    mc.node_hdl = node_create(
        bf.mcast_hdl,
        bf.dev_id,
        rid,
        &mut mc.portmap,
        &mut mc.lagmap,
    )?;

    match associate_node(
        bf.mcast_hdl,
        bf.dev_id,
        domain.mgrp_hdl,
        mc.node_hdl,
        level_1_excl_id,
    ) {
        Ok(_) => {
            domain.ports.insert(port, mc);
            Ok(())
        }
        Err(e) => {
            if let Err(x) = node_destroy(bf.mcast_hdl, bf.dev_id, mc.node_hdl) {
                error!(
                    hdl.log,
                    "post-failure multicast cleanup failed: {:?}", x
                );
                domain.detached_nodes.push(mc.node_hdl);
            }
            Err(e)
        }
    }
}

/// Remove a port from a multicast domain.
pub fn domain_remove_port(
    hdl: &Handle,
    group_id: u16,
    port: u16,
) -> AsicResult<()> {
    debug!(hdl.log, "removing {} from multicast domain {}", port, group_id);
    let mut domains = hdl.domains.lock().unwrap();
    let domain = match domains.get_mut(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::Missing("no such domain".to_string())),
    }?;

    let bf = hdl.bf_get();
    destroy_detached_nodes(&hdl.log, &bf, domain);

    let node_hdl = domain
        .ports
        .get(&port)
        .ok_or_else(|| AsicError::Missing("port not in domain".to_string()))?
        .node_hdl;

    detach_node(
        &hdl.log,
        &bf,
        domain.mgrp_hdl,
        node_hdl,
        &mut domain.detached_nodes,
    )?;

    domain.ports.remove(&port);
    Ok(())
}

/// Create a multicast domain.
pub fn domain_create(hdl: &Handle, group_id: u16) -> AsicResult<()> {
    info!(hdl.log, "creating multicast domain {}", group_id);
    let mut domains = hdl.domains.lock().unwrap();
    if domains.get(&group_id).is_some() {
        return Err(AsicError::Exists(format!(
            "multicast domain {group_id} already exists"
        )));
    };

    let bf = hdl.bf_get();

    let mgrp_hdl = mgrp_create(bf.mcast_hdl, bf.dev_id, group_id)?;
    domains.insert(
        group_id,
        DomainState {
            id: group_id,
            mgrp_hdl,
            ports: HashMap::new(),
            detached_nodes: Vec::new(),
        },
    );
    Ok(())
}

/// Destroy a multicast domain.
pub fn domain_destroy(hdl: &Handle, group_id: u16) -> AsicResult<()> {
    info!(hdl.log, "destroying multicast domain {}", group_id);
    let mut domains = hdl.domains.lock().unwrap();
    let domain = match domains.get_mut(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::Missing("no such domain".to_string())),
    }?;

    let bf = hdl.bf_get();

    let mgrp_hdl = domain.mgrp_hdl;
    let domain_id = domain.id;
    let mut first_err = None;
    domain.ports.retain(|port, mc| {
        if let Err(e) = detach_node(
            &hdl.log,
            &bf,
            mgrp_hdl,
            mc.node_hdl,
            &mut domain.detached_nodes,
        ) {
            error!(
                hdl.log,
                "cleaning up port {} for multicast domain {}: {:?}",
                port,
                domain_id,
                e
            );
            first_err.get_or_insert(e);
            true
        } else {
            false
        }
    });

    if let Some(e) = destroy_detached_nodes(&hdl.log, &bf, domain) {
        first_err.get_or_insert(e);
    }

    if let Some(e) = first_err {
        return Err(e);
    }

    match mgrp_destroy(bf.mcast_hdl, bf.dev_id, mgrp_hdl) {
        Ok(()) | Err(AsicError::Missing(_)) => {
            domains.remove(&group_id);
            Ok(())
        }
        Err(e) => {
            if matches!(
                mgrp_destroy(bf.mcast_hdl, bf.dev_id, mgrp_hdl),
                Ok(()) | Err(AsicError::Missing(_))
            ) {
                domains.remove(&group_id);
            }
            Err(e)
        }
    }
}

/// Domain exists.
pub fn domain_exists(hdl: &Handle, group_id: u16) -> bool {
    let domains = hdl.domains.lock().unwrap();
    domains.contains_key(&group_id)
}

/// Get the total number of multicast domains.
pub fn domains_count(hdl: &Handle) -> AsicResult<usize> {
    let bf = hdl.bf_get();
    mgrp_get_count(hdl, bf.dev_id, 0)
}

/// Set the maximum number of multicast nodes.
pub fn set_max_nodes(
    hdl: &Handle,
    node_count: u32,
    node_port_lag_count: u32,
) -> AsicResult<()> {
    let bf = hdl.bf_get();
    set_max_node_threshold(
        bf.mcast_hdl,
        bf.dev_id,
        node_count as i32,
        node_port_lag_count as i32,
    )
}
