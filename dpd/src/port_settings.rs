// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

// This Source Code Form is subject to the terms of the Mozilla Source
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::api_server::LinkSettings;
use crate::api_server::PortSettings;
use crate::link::Link;
use crate::link::LinkId;
use crate::link::LinkParams;
use crate::DpdError;
use crate::DpdResult;
use crate::Switch;
use aal::AsicOps;
use common::ports::Ipv4Entry;
use common::ports::Ipv6Entry;
use common::ports::PortFec;
use common::ports::PortId;
use common::ports::PortSpeed;
use common::ports::TxEq;
use slog::debug;
use slog::error;
use slog::trace;
use slog::Logger;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// A change set is a plan for how to add, delete and modify a set of objects
/// with type `V` indexed by type `K`.
#[derive(Debug, Clone)]
struct ChangeSet<K, V> {
    add: HashMap<K, ChangeNode<V>>,
    delete: HashMap<K, ChangeNode<V>>,
    modify: HashMap<K, ChangeNode<Modify<V>>>,
}

// Why not derive Default? See https://github.com/rust-lang/rust/issues/26925.
impl<K, V> Default for ChangeSet<K, V> {
    fn default() -> Self {
        Self {
            add: HashMap::default(),
            delete: HashMap::default(),
            modify: HashMap::default(),
        }
    }
}

/// A change node keeps track of the state of an object in a change set. Objects
/// start out as `Unchanged` and can transition to `Changed` or `Failed`.
#[derive(Debug, Clone)]
enum ChangeNode<T> {
    Unchanged(T),
    Changed(T),
    Failed(T),
}

impl<T: Clone> ChangeNode<T> {
    fn data(&self) -> &T {
        match self {
            Self::Unchanged(x) => x,
            Self::Changed(x) => x,
            Self::Failed(x) => x,
        }
    }
    /// A helper function to transition a state to `Changed` or `Failed` based
    /// on a result. This is to reduce boilerplate and make the logic of the
    /// `PortSettingsDiff::do_execute` function easier to read.
    fn transition(&mut self, result: DpdResult<()>) -> DpdResult<()> {
        // TODO possible to do this without a clone e.g. just change the variant
        // around the data?
        match &result {
            Ok(_) => *self = Self::Changed(self.data().clone()),
            Err(_) => *self = Self::Failed(self.data().clone()),
        }
        result
    }
}

/// A general struct to keep track of objects changing from `before` to `after`.
#[derive(Clone, Debug)]
struct Modify<T> {
    pub before: T,
    pub after: T,
}

/// A [`LinkSpec`] is an intermediate representation of a link between the
/// top level dpd API representation and the lower level ASIC representation.
#[derive(Clone, PartialEq, Debug)]
struct LinkSpec {
    pub speed: PortSpeed,
    pub fec: Option<PortFec>,
    pub autoneg: bool,
    pub kr: bool,
    pub delete_me: bool,
    pub ipv4: BTreeSet<Ipv4Addr>,
    pub ipv6: BTreeSet<Ipv6Addr>,
    pub tx_eq: Option<TxEq>,
}

impl From<&Link> for LinkSpec {
    fn from(p: &Link) -> Self {
        Self {
            speed: p.config.speed,
            fec: p.config.fec,
            autoneg: p.config.autoneg,
            kr: p.config.kr,
            tx_eq: p.tx_eq,
            delete_me: p.config.delete_me,
            ipv4: p.ipv4.iter().map(|x| x.addr).collect(),
            ipv6: p.ipv6.iter().map(|x| x.addr).collect(),
        }
    }
}

impl From<&LinkSettings> for LinkSpec {
    fn from(l: &LinkSettings) -> Self {
        Self {
            speed: l.params.speed,
            fec: l.params.fec,
            autoneg: l.params.autoneg,
            kr: l.params.kr,
            tx_eq: l.params.tx_eq,
            delete_me: false,
            ipv4: l
                .addrs
                .iter()
                .filter_map(
                    |x| if let IpAddr::V4(a) = x { Some(a) } else { None },
                )
                .copied()
                .collect(),
            ipv6: l
                .addrs
                .iter()
                .filter_map(
                    |x| if let IpAddr::V6(a) = x { Some(a) } else { None },
                )
                .copied()
                .collect(),
        }
    }
}

/// When a port settings update is created, this diff is calculated as a plan
/// for what needs to be done.
#[derive(Default, Clone, Debug)]
struct PortSettingsDiff {
    /// Link change set.
    links: ChangeSet<LinkId, LinkSpec>,
}

impl PortSettingsDiff {
    /// Calculate a port settings diff between the prescibed settings and the
    /// resident state on the switch.
    fn calculate(
        ctx: &mut Context<'_>,
        settings: &PortSettings,
    ) -> DpdResult<Self> {
        let mut diff = Self::default();

        diff.calculate_links(ctx, settings)?;

        Ok(diff)
    }

    /// Calculate the change set between prescribed links and resident links on
    /// the switch.
    fn calculate_links(
        &mut self,
        ctx: &mut Context<'_>,
        settings: &PortSettings,
    ) -> DpdResult<()> {
        // Collect the links required by settings
        let settings_links: BTreeSet<LinkId> =
            settings.links.keys().copied().map(LinkId::from).collect();

        // Collect all the links that exist on the port.
        let switch_links = ctx.link_map.port_links(ctx.port_id);

        // Determine what we need to add/delete/modify
        let links_to_add = settings_links.difference(&switch_links);
        let links_to_del = switch_links.difference(&settings_links);
        let links_to_mod = switch_links.intersection(&settings_links);

        self.links.add = links_to_add
            .map(|id| {
                (*id, ChangeNode::Unchanged((&settings.links[&id.0]).into()))
            })
            .collect();

        self.links.delete = links_to_del
            .map(|id| {
                (
                    *id,
                    ChangeNode::Unchanged(ctx.link_spec(*id).expect(
                        "link existence is guaranteed by the locked link map",
                    )),
                )
            })
            .collect();

        self.links.modify = links_to_mod
            .map(|id| {
                let settings_link = (&settings.links[&id.0]).into();
                let switch_link = ctx.link_spec(*id).expect(
                    "link existence is guaranteed by the locked link map",
                );
                (id, settings_link, switch_link)
            })
            .filter(|(_, settings, switch)| settings != switch)
            .map(|(id, settings, switch)| {
                (
                    *id,
                    ChangeNode::Unchanged(Modify {
                        before: switch,
                        after: settings,
                    }),
                )
            })
            .collect();

        Ok(())
    }

    /// Execute a change set. Attempting to roll back if there is an error.
    fn execute(&mut self, ctx: &mut Context<'_>) -> DpdResult<()> {
        let mut rb = Rollback::default();
        if let Err(e) = self.do_execute(ctx, &mut rb) {
            slog::error!(ctx.log, "port_settings op failed: {e:?}");
            match rb.unwind(ctx) {
                Err(ue) => {
                    slog::error!(
                        ctx.log,
                        "port_settings unwind failed: {ue:?}"
                    );
                    // If there is an unwind error, send back a more specific
                    // error, containing the initial error and the unwind error.
                    return Err(DpdError::Unwind {
                        initial: Box::new(e),
                        unwind: Box::new(ue),
                    });
                }
                Ok(_) => return Err(e),
            }
        }
        Ok(())
    }

    fn do_execute(
        &mut self,
        ctx: &mut Context<'_>,
        rb: &mut Rollback,
    ) -> DpdResult<()> {
        // Delete - the order is important here, routes must be deleted before
        // links as routes are defined in terms of links.
        for (id, change) in &mut self.links.delete {
            slog::trace!(ctx.log, "delete link {}/{}", ctx.port_id, *id);
            change.transition(Self::remove_link(
                ctx,
                *id,
                change.data(),
                rb,
            ))?;
            ctx.switch.reconciler.trigger(ctx.port_id, *id);
            slog::trace!(ctx.log, "delete link -> {:?}", change);
        }

        // Add
        for (id, change) in &mut self.links.add {
            slog::trace!(ctx.log, "add link {}/{}", ctx.port_id, *id);
            change.transition(Self::add_link(ctx, *id, change.data(), rb))?;
            ctx.switch.reconciler.trigger(ctx.port_id, *id);
            slog::trace!(ctx.log, "add link -> {:#?}", change);
        }

        // Modify
        for (id, change) in &mut self.links.modify {
            slog::trace!(ctx.log, "modify link {}/{}", ctx.port_id, *id);
            change.transition(Self::modify_link(
                ctx,
                *id,
                change.data(),
                rb,
            ))?;
            ctx.switch.reconciler.trigger(ctx.port_id, *id);
            slog::trace!(ctx.log, "modify link -> {:#?}", change);
        }

        Ok(())
    }

    fn add_link(
        ctx: &mut Context<'_>,
        link_id: LinkId,
        spec: &LinkSpec,
        rb: &mut Rollback,
    ) -> DpdResult<()> {
        let mac = ctx.switch.allocate_mac_address(ctx.port_id, link_id)?;
        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            ctx.switch.free_mac_address(mac);
            Ok(())
        });

        let params = LinkParams {
            speed: spec.speed,
            autoneg: spec.autoneg,
            kr: spec.kr,
            tx_eq: spec.tx_eq,
            fec: spec.fec,
        };
        let port_id = ctx.port_id;
        let asic_port_id = ctx.switch.port_link_to_asic_id(port_id, link_id)?;
        let port_hdl = ctx.switch.asic_hdl.asic_id_to_port(asic_port_id)?;
        // Create the link object
        // TODO: the PortSettings stuff should allow the caller to request a
        // specific starting lane.  That functionality currently has no consumer
        // on the Omicron side, but it will eventually.
        let mut link = Link::new(
            port_id,
            link_id,
            port_hdl,
            asic_port_id,
            params.clone(),
            mac,
        );

        link.config.enabled = true;
        ctx.link_map.insert_link(link)?;
        let link_lock = ctx
            .link_map
            .get_link(port_id, link_id)
            .expect("the link was just inserted, so it must exist");
        let mut link = link_lock.lock().unwrap();

        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            (*ctx.link_map)
                .delete_link(ctx.port_id, link_id)
                .expect("link existence is guaranteed by the link_map lock");
            Ok(())
        });

        // Create the IPv4 addresses
        for addr in spec.ipv4.iter().copied() {
            Self::addr_add_v4(ctx, &mut link, rb, addr)?;
        }

        // Create the IPv6 addresses
        for addr in spec.ipv6.iter().copied() {
            Self::addr_add_v6(ctx, &mut link, rb, addr)?;
        }

        Ok(())
    }

    fn remove_link(
        ctx: &mut Context<'_>,
        link_id: LinkId,
        spec: &LinkSpec,
        rb: &mut Rollback,
    ) -> DpdResult<()> {
        debug!(ctx.log, "removing link");
        let link_lock = ctx.link(link_id)?;
        let mut link = link_lock.lock().unwrap();

        link.config.delete_me = true;
        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            link.config.delete_me = false;
            Ok(())
        });

        // Delete the IPv4 addresses
        for addr in spec.ipv4.iter().copied() {
            Self::addr_del_v4(ctx, &mut link, rb, addr)?;
        }

        // Delete the IPv6 addresses
        for addr in spec.ipv6.iter().copied() {
            Self::addr_del_v6(ctx, &mut link, rb, addr)?;
        }

        Ok(())
    }

    fn modify_link(
        ctx: &mut Context<'_>,
        link_id: LinkId,
        spec: &Modify<LinkSpec>,
        rb: &mut Rollback,
    ) -> DpdResult<()> {
        // unsupported things
        // XXX: we actually could support this now, as the reconciler task will
        // do the necessary cleanup before attempting to apply the changes.
        if spec.before.speed != spec.after.speed {
            return Err(DpdError::Invalid(
                "changing link speed not supported, recreate required".into(),
            ));
        }
        if spec.before.fec != spec.after.fec {
            return Err(DpdError::Invalid(
                "changing link fec not supported, recreate required".into(),
            ));
        }

        let link_lock = ctx.link(link_id)?;
        let mut link = link_lock.lock().unwrap();

        let an_before = spec.before.autoneg;
        let kr_before = spec.before.kr;
        let txeq_before = spec.before.tx_eq;
        let delete_before = spec.before.delete_me;
        link.config.autoneg = spec.after.autoneg;
        link.config.kr = spec.after.kr;
        link.tx_eq = spec.after.tx_eq;
        link.config.delete_me = false;
        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            link.config.autoneg = an_before;
            link.config.kr = kr_before;
            link.tx_eq = txeq_before;
            link.config.delete_me = delete_before;
            Ok(())
        });

        // ipv4 addrs
        let v4_add: BTreeSet<Ipv4Addr> = spec
            .after
            .ipv4
            .difference(&spec.before.ipv4)
            .copied()
            .collect();

        let v4_del: BTreeSet<Ipv4Addr> = spec
            .before
            .ipv4
            .difference(&spec.after.ipv4)
            .copied()
            .collect();

        for addr in v4_add {
            Self::addr_add_v4(ctx, &mut link, rb, addr)?;
        }
        for addr in v4_del {
            Self::addr_del_v4(ctx, &mut link, rb, addr)?;
        }

        // ipv6 addrs
        let v6_add: BTreeSet<Ipv6Addr> = spec
            .after
            .ipv6
            .difference(&spec.before.ipv6)
            .copied()
            .collect();

        let v6_del: BTreeSet<Ipv6Addr> = spec
            .before
            .ipv6
            .difference(&spec.after.ipv6)
            .copied()
            .collect();

        for addr in v6_add {
            Self::addr_add_v6(ctx, &mut link, rb, addr)?;
        }
        for addr in v6_del {
            Self::addr_del_v6(ctx, &mut link, rb, addr)?;
        }

        Ok(())
    }

    fn addr_add_v4(
        ctx: &mut Context<'_>,
        link: &mut Link,
        rb: &mut Rollback,
        addr: Ipv4Addr,
    ) -> DpdResult<()> {
        trace!(ctx.log, "ipv4 add {addr}");
        // Create address on ASIC first.
        let entry = Ipv4Entry {
            tag: ctx.tag.clone().unwrap_or("".into()),
            addr,
        };
        let switch = ctx.switch;
        switch.create_ipv4_address_locked(link, entry)?;

        let link_id = link.link_id;
        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let switch = ctx.switch;
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            switch.delete_ipv4_address_locked(&mut link, addr)
        });
        Ok(())
    }

    fn addr_del_v4(
        ctx: &mut Context<'_>,
        link: &mut Link,
        rb: &mut Rollback,
        addr: Ipv4Addr,
    ) -> DpdResult<()> {
        trace!(ctx.log, "ipv4 del {addr}");
        let entry = Ipv4Entry {
            tag: ctx.tag.clone().unwrap_or("".into()),
            addr,
        };
        let switch = ctx.switch;
        let link_id = link.link_id;
        switch.delete_ipv4_address_locked(link, addr)?;

        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let switch = ctx.switch;
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            switch.create_ipv4_address_locked(&mut link, entry)
        });
        Ok(())
    }

    fn addr_add_v6(
        ctx: &mut Context<'_>,
        link: &mut Link,
        rb: &mut Rollback,
        addr: Ipv6Addr,
    ) -> DpdResult<()> {
        trace!(ctx.log, "ipv6 add {addr}");
        // Create address on ASIC first.
        let entry = Ipv6Entry {
            tag: ctx.tag.clone().unwrap_or("".into()),
            addr,
        };
        let switch = ctx.switch;
        let link_id = link.link_id;
        switch.create_ipv6_address_locked(link, entry)?;

        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let switch = ctx.switch;
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            switch.delete_ipv6_address_locked(&mut link, addr)
        });
        Ok(())
    }

    fn addr_del_v6(
        ctx: &mut Context<'_>,
        link: &mut Link,
        rb: &mut Rollback,
        addr: Ipv6Addr,
    ) -> DpdResult<()> {
        trace!(ctx.log, "ipv6 del {addr}");
        let switch = ctx.switch;
        let link_id = link.link_id;
        switch.delete_ipv6_address_locked(link, addr)?;

        rb.wind(move |ctx: &mut Context<'_>| -> DpdResult<()> {
            let entry = Ipv6Entry {
                tag: ctx.tag.clone().unwrap_or("".into()),
                addr,
            };
            let switch = ctx.switch;
            let link_lock = ctx.link(link_id)?;
            let mut link = link_lock.lock().unwrap();
            switch.create_ipv6_address_locked(&mut link, entry)
        });
        Ok(())
    }
}

type UnrollFn = dyn FnOnce(&mut Context<'_>) -> DpdResult<()>;

#[derive(Default)]
struct Rollback(Vec<Box<UnrollFn>>);

impl Rollback {
    fn wind(
        &mut self,
        f: impl FnOnce(&mut Context<'_>) -> DpdResult<()> + 'static,
    ) {
        self.0.push(Box::new(f));
    }

    fn unwind(&mut self, ctx: &mut Context<'_>) -> DpdResult<()> {
        let mut result = Ok(());
        ctx.rollback = true;
        while let Some(f) = self.0.pop() {
            if let Err(e) = f(ctx) {
                error!(ctx.log, "rollback: {}", e);
                result = Err(e);
            }
        }
        result
    }
}

/// The port settings context contains information needed to execute a port
/// settings update transaction. Notably, the `link_map` comes from a lock
/// guard, which guarantees that its contents can not be modified by other
/// threads during transaction execution.
struct Context<'a> {
    port_id: PortId,
    switch: &'a Switch,
    link_map: MutexGuard<'a, crate::link::LinkMap>,
    tag: Option<String>,
    log: Logger,
    rollback: bool,
}

macro_rules! context {
    ($port_id:expr, $switch:expr) => {
        Context {
            port_id: $port_id,
            switch: $switch,
            link_map: $switch.links.lock().unwrap(),
            tag: None,
            log: $switch.log.clone(),
            rollback: false,
        }
    };
}

impl Context<'_> {
    fn link(&mut self, link_id: LinkId) -> DpdResult<Arc<Mutex<Link>>> {
        self.link_map.get_link(self.port_id, link_id)
    }

    fn link_spec(&mut self, link_id: LinkId) -> DpdResult<LinkSpec> {
        let link_lock = self.link_map.get_link(self.port_id, link_id)?;
        let link = link_lock.lock().unwrap();
        Ok(LinkSpec::from(&*link))
    }
}

impl Switch {
    /// Apply port settings as an atomic transaction.
    pub async fn apply_port_settings(
        &self,
        port_id: PortId,
        settings: PortSettings,
        tag: Option<String>,
    ) -> DpdResult<PortSettings> {
        let mut ctx = context!(port_id, self);
        ctx.tag = tag;

        let mut diff = PortSettingsDiff::calculate(&mut ctx, &settings)?;
        trace!(self.log, "port settings diff: {:#?}", diff);
        diff.execute(&mut ctx)?;

        Self::get_port_settings_locked(&mut ctx, true)
    }

    /// Clear port settings as an atomic transaction.
    pub async fn clear_port_settings(
        &self,
        port_id: PortId,
        tag: Option<String>,
    ) -> DpdResult<PortSettings> {
        let mut ctx = context!(port_id, self);
        ctx.tag = tag;

        let settings = PortSettings::default();
        let mut diff = PortSettingsDiff::calculate(&mut ctx, &settings)?;
        trace!(self.log, "port settings diff: {:#?}", diff);
        diff.execute(&mut ctx)?;

        Self::get_port_settings_locked(&mut ctx, true)
    }

    /// Get port settings as an atomic transaction.
    pub async fn get_port_settings(
        &self,
        port_id: PortId,
        tag: Option<String>,
    ) -> DpdResult<PortSettings> {
        let mut ctx = context!(port_id, self);
        ctx.tag = tag;
        Self::get_port_settings_locked(&mut ctx, false)
    }

    fn get_port_settings_locked(
        ctx: &mut Context<'_>,
        ignore_deleting: bool,
    ) -> DpdResult<PortSettings> {
        let links = ctx
            .link_map
            .get_links()
            .iter()
            .filter_map(|((port_id, link_id), link_lock)| {
                if *port_id == ctx.port_id {
                    let link = link_lock.lock().unwrap();

                    // This is an awkward mechanism to work around the
                    // asynchrony of link deletion.  When we return the
                    // PortSettings as a side effect of the apply() and clear()
                    // operations, we assume that any requested link deletion
                    // will succeed - as indeed it almost certainly will.  This
                    // optimism is primarily to allow the chaos tests to pass,
                    // since they have no mechanism to wait for this async
                    // operation to complete.  Arguably, we should simply stop
                    // returning anything other than success or failure on these
                    // operations.
                    //
                    // If we get an explicit request for the current settings,
                    // we will return the actual state of any link marked for
                    // deletion.  This allows the chaos tests to run correctly
                    // even in the presence of repeated artificial errors.  More
                    // importantly, it also ensures that a real consumer of the
                    // port_settings API will be operating on the correct
                    // information.
                    if ignore_deleting && link.config.delete_me {
                        None
                    } else {
                        Some(((*link_id).into(), LinkSettings::from(&*link)))
                    }
                } else {
                    None
                }
            })
            .collect();
        Ok(PortSettings { links })
    }
}
