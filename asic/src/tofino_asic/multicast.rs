// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;

use slog::{debug, error, info};

use crate::tofino_asic::bf_wrapper::*;
use crate::tofino_asic::genpd::*;
use crate::tofino_asic::{CheckError, Handle};
use crate::tofino_asic::{BF_MC_LAG_ARRAY_SIZE, BF_MC_PORT_ARRAY_SIZE};

use aal::{AsicError, AsicResult};

pub struct DomainState {
    id: u16,
    mgrp_hdl: bf_mc_mgrp_hdl_t,
    ports: HashMap<u16, MulticastState>,
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
            true,
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
    unsafe {
        bf_mc_dissociate_node(mcast_hdl, dev_id, mgrp_hdl, node_hdl)
            .check_error("dissociating multicast node from group")?;
    }
    Ok(())
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

fn cleanup_node(
    bf: &BfCommon,
    mgrp_hdl: Option<bf_mc_mgrp_hdl_t>,
    port_state: &MulticastState,
) -> AsicResult<()> {
    if let Some(mgrp_hdl) = mgrp_hdl {
        dissociate_node(
            bf.mcast_hdl,
            bf.dev_id,
            mgrp_hdl,
            port_state.node_hdl,
        )?;
    }

    node_destroy(bf.mcast_hdl, bf.dev_id, port_state.node_hdl)
}

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

pub fn domain_port_count(hdl: &Handle, group_id: u16) -> AsicResult<usize> {
    let mut domains = hdl.domains.lock().unwrap();
    match domains.get_mut(&group_id) {
        Some(d) => Ok(d.ports.len()),
        None => Err(AsicError::InvalidArg("no such domain domain".to_string())),
    }
}

pub fn domain_add_port(
    hdl: &Handle,
    group_id: u16,
    port: u16,
) -> AsicResult<()> {
    debug!(
        hdl.log,
        "adding port {} to multicast domain {}", port, group_id
    );
    let mut domains = hdl.domains.lock().unwrap();
    let domain = match domains.get_mut(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::InvalidArg("no such domain domain".to_string())),
    }?;

    if domain.ports.contains_key(&port) {
        return Err(AsicError::InvalidArg(
            "port already in domain".to_string(),
        ));
    }

    let bf = hdl.bf_get();

    let mut mc = MulticastState {
        node_hdl: 0,
        portmap: vec![0u8; BF_MC_PORT_ARRAY_SIZE],
        lagmap: vec![0u8; BF_MC_LAG_ARRAY_SIZE],
    };

    bit_set(&mut mc.portmap, port);
    mc.node_hdl = node_create(
        bf.mcast_hdl,
        bf.dev_id,
        port, // Use port_id as the replication ID
        &mut mc.portmap,
        &mut mc.lagmap,
    )?;

    match associate_node(
        bf.mcast_hdl,
        bf.dev_id,
        domain.mgrp_hdl,
        mc.node_hdl,
        port, // use the port number as the l1 exclusion ID
    ) {
        Ok(_) => {
            domain.ports.insert(port, mc);
            Ok(())
        }
        Err(e) => {
            if let Err(x) = cleanup_node(&bf, None, &mc) {
                error!(
                    hdl.log,
                    "post-failure multicast cleanup failed: {:?}", x
                );
            }
            Err(e)
        }
    }
}

pub fn domain_remove_port(
    hdl: &Handle,
    group_id: u16,
    port: u16,
) -> AsicResult<()> {
    debug!(
        hdl.log,
        "removing {} from multicast domain {}", port, group_id
    );
    let mut domains = hdl.domains.lock().unwrap();
    let domain = match domains.get_mut(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::InvalidArg("no such domain domain".to_string())),
    }?;

    let bf = hdl.bf_get();

    let mc = match domain.ports.remove(&port) {
        Some(n) => n,
        None => {
            return Err(AsicError::InvalidArg("port not in domain".to_string()))
        }
    };

    cleanup_node(&bf, Some(domain.mgrp_hdl), &mc)?;
    Ok(())
}

pub fn domain_create(hdl: &Handle, group_id: u16) -> AsicResult<()> {
    info!(hdl.log, "creating multicast domain {}", group_id);
    let mut domains = hdl.domains.lock().unwrap();
    if domains.get(&group_id).is_some() {
        return Err(AsicError::InvalidArg("domain already exists".to_string()));
    };

    let bf = hdl.bf_get();

    let mgrp_hdl = mgrp_create(bf.mcast_hdl, bf.dev_id, group_id)?;
    domains.insert(
        group_id,
        DomainState {
            id: group_id,
            mgrp_hdl,
            ports: HashMap::new(),
        },
    );
    Ok(())
}

pub fn domain_destroy(hdl: &Handle, group_id: u16) -> AsicResult<()> {
    info!(hdl.log, "destroying multicast domain {}", group_id);
    let mut domains = hdl.domains.lock().unwrap();
    let mut domain = match domains.remove(&group_id) {
        Some(d) => Ok(d),
        None => Err(AsicError::InvalidArg("no such domain".to_string())),
    }?;

    let bf = hdl.bf_get();

    let mgrp_hdl = domain.mgrp_hdl;
    for (port, mc) in domain.ports.drain() {
        if let Err(e) = cleanup_node(&bf, Some(mgrp_hdl), &mc) {
            error!(
                hdl.log,
                "cleaning up port {} for multicast domain {}: {:?}",
                port,
                domain.id,
                e
            );
        }
    }

    mgrp_destroy(bf.mcast_hdl, bf.dev_id, domain.mgrp_hdl)
}
