// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeSet;

use slog::debug;
use slog::o;

use crate::link::LinkId;
use crate::types::DpdError;
use crate::types::DpdResult;
use crate::Switch;
use common::network::MacAddr;
use common::ports::PortId;
use common::ports::PORT_COUNT_INTERNAL;
use common::ports::PORT_COUNT_QSFP;
use common::ports::PORT_COUNT_REAR;

cfg_if::cfg_if! {
    if #[cfg(feature = "tofino_asic")] {
        use std::convert::TryFrom;
    use crate::api_server::LinkCreate;
        use common::ports::PortFec;
        use common::ports::PortSpeed;
        use common::ports::InternalPort;
        use transceiver_controller::Error as TransceiverError;
    }
}

// Each switch is allocated a range of 256 mac addresses.  The SP claims two of
// those, and the remaining 254 can then be assigned to links created on the
// switch.  Currently, the first 161 of those addresses are statically assigned
// to links based on their type and identity. The first mac address is assigned
// to the internal/cpu port.  The next 32 are assigned to the rear ports,
// assuming that each will have no more than one link configured.  The final 128
// are assigned to the 32 front/qsfp ports, assuming that each will have no more
// than 4 links configured.
//
// These limits are expected to be sufficient for normal use both internally and
// at customer sites.  If those limits are exceeded during bringup, diagnostics,
// or other experimental configurations, additional mac addresses may be
// dynamically allocated from the range of addresses from 162-254.

// maximum expected links on an internal port
const LINKS_PER_INTERNAL: u16 = 1;
// maximum expected links on a rear port
const LINKS_PER_REAR: u16 = 1;
// maximum expected links on a front/qsfp port
const LINKS_PER_QSFP: u16 = 4;

// start of the mac address range reserved for internal ports
const MAC_OFFSET_INTERNAL: u16 = 0;
// start of the mac address range reserved for rear ports
const MAC_OFFSET_REAR: u16 = PORT_COUNT_INTERNAL as u16 * LINKS_PER_INTERNAL;
// start of the mac address range reserved for front/qsfp ports
const MAC_OFFSET_QSFP: u16 =
    MAC_OFFSET_REAR + PORT_COUNT_REAR as u16 * LINKS_PER_REAR;

// bounds of the pool of addresses that may be dynamically assigned
const DYNAMIC_MAC_POOL_START: u16 =
    MAC_OFFSET_QSFP + PORT_COUNT_QSFP as u16 * LINKS_PER_QSFP;
const DYNAMIC_MAC_POOL_END: u16 = 254;

/// Data structure for managing the allocation of mac addresses for this switch
//
// We track allocations of both static and dynamic mac addresses using a hashset
// containing offsets from the beginning of the mac address range.  The dynamic
// tracking structure is consulted when allocating a new address.  The static
// tracking is only used a sanity check mechanism, so we can catch mis-matched
// link creations/deletions.
pub struct MacManagement {
    log: slog::Logger,
    base_mac: Option<BaseMac>,
    static_pool: BTreeSet<u16>,
    dynamic_pool: BTreeSet<u16>,
    allocation_count: u32,
}

/// The base MAC address from which others are allocated.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum BaseMac {
    /// The MAC is temporary, and will be replaced.
    ///
    /// No MACs beyond that for the link on the CPU port will be allocated while
    /// this is the case.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    Temporary(MacAddr),
    /// The MAC is permanent.
    ///
    /// A MAC address for any link can be allocated from this. Note that the
    /// base MAC may still be random, as is the case when we run `dpd` on
    /// non-Tofino systems -- in that case, we generate a fake, random MAC for
    /// the system.
    Permanent(MacAddr),
}

impl core::fmt::Display for BaseMac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl BaseMac {
    /// Return the contained MAC address.
    pub fn mac_addr(&self) -> MacAddr {
        match self {
            Self::Temporary(inner) => *inner,
            Self::Permanent(inner) => *inner,
        }
    }
}

impl MacManagement {
    pub fn new(log: &slog::Logger) -> Self {
        let log = log.new(o!("unit" => "macmgmt"));
        debug!(log, "creating MacManagement");
        MacManagement {
            log,
            base_mac: None,
            static_pool: (MAC_OFFSET_INTERNAL..DYNAMIC_MAC_POOL_START)
                .collect(),
            dynamic_pool: (DYNAMIC_MAC_POOL_START..DYNAMIC_MAC_POOL_END)
                .collect(),
            allocation_count: 0,
        }
    }

    /// Replace the base mac address, returning the old value.
    pub(crate) fn set_base_mac(
        &mut self,
        base_mac: BaseMac,
    ) -> DpdResult<Option<BaseMac>> {
        if self.allocation_count != 0 {
            Err(DpdError::Busy(
                "Can't update base_mac with outstanding mac allocations".into(),
            ))
        } else {
            // Check that we're moving only in one direction, towards more
            // permanent addresses.
            match (&self.base_mac, &base_mac) {
                (None, BaseMac::Temporary(_))
                | (None, BaseMac::Permanent(_))
                | (Some(BaseMac::Temporary(_)), BaseMac::Permanent(_)) => {}
                (_, _) => return Err(DpdError::InvalidNewBaseMacAddr),
            }
            debug!(
                self.log, "replacing base_mac address";
                    "old" => ?self.base_mac,
                    "new" => %base_mac
            );
            Ok(self.base_mac.replace(base_mac))
        }
    }

    /// Generate a new MAC address for the provided port and link.
    ///
    /// This first attempts to construct a MAC using the deterministic
    /// allocation policy. If this fails (most likely because the number of
    /// links on the port exceeds the intended limit), it will then attempt to
    /// allocate an address from the dynamic pool.
    ///
    /// If the base MAC in self is temporary, this will fail for a link on any
    /// port other than the CPU port. In that case, we allow creating a
    /// temporary link from a random base MAC, so that we can actually fetch the
    /// real base MAC from the Sidecar FRUID over the management network. The
    /// link will be torn down after we fetch that, and the base MAC replaced
    /// with the real one.
    pub fn allocate_mac_address(
        &mut self,
        port_id: PortId,
        link_id: LinkId,
    ) -> Option<MacAddr> {
        // Check that we have a base MAC, and that we're allowed to allocate
        // anything beyond the CPU link.
        let base_mac = match self.base_mac {
            None => return None,
            Some(BaseMac::Permanent(base_mac)) => base_mac,
            Some(BaseMac::Temporary(base_mac)) => {
                if !matches!(port_id, PortId::Internal(_)) {
                    return None;
                }
                base_mac
            }
        };

        match mac_offset(port_id, link_id) {
            Some(offset) => {
                debug!(self.log, "allocated static offset";
                    "offset" => offset,
                    "port_id" => %port_id,
                    "link_id" => %link_id,
                );
                assert!(self.static_pool.remove(&offset));
                Some(offset)
            }
            None => {
                let offset = self.dynamic_pool.pop_first();
                debug!(self.log, "allocated dynamic offset";
                    "offset" => offset,
                    "port_id" => %port_id,
                    "link_id" => %link_id,
                );
                offset
            }
        }
        .map(|offset|
        // The safety of this addition here is mostly guaranteed by the
        // `transceiver_messages::MacAddrs` type, which verifies that the full
        // range of addresses are valid and within the same OUI.
        MacAddr::from(u64::from(base_mac) + u64::from(offset)))
        .inspect(|_| {
            self.allocation_count += 1;
        })
    }

    /// Pull a specific mac address from the appropriate pool.  This is only
    /// done when the port_settings code is rolling back a failed update, and is
    /// trying to recreate a link that it had just deleted.
    pub fn reclaim_mac_address(&mut self, mac: MacAddr) {
        let offset = (u64::from(mac)
            - u64::from(self.base_mac.unwrap().mac_addr()))
            as u16;
        if offset < DYNAMIC_MAC_POOL_START {
            debug!(self.log, "reclaimed static offset";
                "offset" => offset);
            assert!(self.static_pool.remove(&offset));
        } else {
            debug!(self.log, "reclaimed dynamic offset";
                "offset" => offset);
            assert!(self.dynamic_pool.remove(&offset));
        }
        self.allocation_count += 1;
    }

    /// Release an allocated mac address
    pub fn free_mac_address(&mut self, mac: MacAddr) {
        let offset = (u64::from(mac)
            - u64::from(self.base_mac.unwrap().mac_addr()))
            as u16;
        if offset < DYNAMIC_MAC_POOL_START {
            debug!(self.log, "freed static offset";
                "offset" => offset);
            assert!(self.static_pool.insert(offset));
        } else {
            debug!(self.log, "freed dynamic offset";
                "offset" => offset);
            assert!(self.dynamic_pool.insert(offset));
        }
        self.allocation_count -= 1;
    }
}

// Ask the SP for the base MAC address stored in its FRUID.
//
// This does not return until we successfully retrieve the base MAC.
#[cfg(feature = "tofino_asic")]
impl Switch {
    async fn fetch_base_mac_from_sp(&self) -> MacAddr {
        loop {
            // Fetch the base MAC address range, retrying until we succeed.
            //
            // We'll break out of this loop if:
            //
            // - We have no controller yet (it's still being created)
            // - The controller is defunct.
            //
            // Note that this all _requires_ that someone has started the task
            // creating the controller in the first place.
            // `TransceiverState::new()` does that if there is a transceiver
            // interface, so that should be OK. But it's important that we keep
            // that invariant here.
            let need_rebuild = {
                match self.transceiver_controller().await {
                    Err(_) => {
                        debug!(
                            self.log,
                            "transceiver controller does not yet exist"
                        );
                        false
                    }
                    Ok(controller) => {
                        match controller.mac_addrs().await {
                            Err(e) => {
                                // This IO error is returned from the
                                // `Controller` if it fails to send or receive
                                // on the socket itself. Because we cannot
                                // _construct_ a `Controller` until we have a
                                // valid, bound UDP socket, this usually means
                                // the socket has been compromised in the
                                // meantime, such as the IP address or the link
                                // underneath it being deleted.
                                //
                                // This would happen for example, if `tfportd`
                                // were instructed via SIGUSR2 to delete and
                                // recreate all `tfports` and VLANs, which
                                // includes the `sidecar0` interface that we use
                                // to talk to the SP. This should not happen
                                // frequently, or ideally ever, but it's
                                // extremly useful during development to not
                                // get into an unrecoverable state if we do need
                                // to tear down the VLAN interface or IP
                                // address.
                                if let TransceiverError::Io(err) = e {
                                    slog::error!(
                                        self.log,
                                        "IO error fetching MAC addresses, controller \
                                        is compromised and will be rebuilt";
                                        "reason" => err,
                                    );
                                    true
                                } else {
                                    // Continue the fetch loop, the request just failed,
                                    // but the controller itself is still usable.
                                    slog::error!(
                                        self.log,
                                        "failed to fetch MAC addresses from SP";
                                        "reason" => ?e,
                                    );
                                    false
                                }
                            }
                            Ok(macs) => {
                                debug!(
                                    self.log,
                                    "fetched MAC addresses from SP";
                                    "macs" => ?macs,
                                );
                                // We've got a MAC, return it!
                                return MacAddr::from(
                                    macs.iter().next().expect(
                                        "Received zero MACs from Sidecar FRUID",
                                    ),
                                );
                            }
                        }
                    }
                }
            };
            if need_rebuild {
                self.transceivers.trigger_rebuild().await;
            }

            // We wait for a bit regardless of why we're continuing the loop.
            //
            // We may continue if:
            //
            // - The controller doesn't exist.
            // - We got an IO error and need to rebuild the controller.
            // - We got no response from the SP.
            //
            // In the first case, that could be because `tfportd` hasn't created
            // the `sidecar0` VLAN interface we use. In the second, we just want
            // to avoid racing the rebuild task, and needlessly re-acquire the
            // RW lock around the controller. In the latter, we have some
            // non-zero interval in the internal retry-loop of the controller
            // itself, so a bit more is pretty harmless.
            //
            // All that is to say, this is basically arbitrary, but to just
            // avoid spamming a few different components as we try to achieve
            // steady-state.
            const RETRY_INTERVAL: std::time::Duration =
                std::time::Duration::from_secs(1);
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }

    // We may start `dpd` without a base MAC address for assigning addresses to
    // links. In that situation, we need to fetch the base MAC from the Sidecar
    // SP via the management network. This presents us with a bootstrapping
    // problem: we need a MAC to bring up that link, via which we'd fetch the
    // MACs. To break the circularity, we will use a random MAC to temporarily
    // bring up the CPU link; fetch the real MAC addresses; tear down the CPU
    // link; and the continue as normal. We'll cache that as an SMF property to
    // avoid the complexity each time we restart.
    //
    // In general, our process is:
    //
    // - Create a link on the CPU port, using a random MAC address.
    // - Create a transceiver controller. This _will block_ until tfportd makes
    //   us the `sidecar0` VLAN interface that we're expecting to use.
    // - Fetch the MAC address range from the SP using the controller.
    // - Update the MAC address on the CPU link with the final address derived
    //   from the base_mac
    pub async fn set_base_mac_address(
        &self,
        autoconfig_links: &Option<crate::AutoconfiguredLinks>,
    ) -> anyhow::Result<bool> {
        slog::info!(
            self.log,
            "no base MAC address found, fetching from Sidecar FRUID"
        );

        // Get the parameters used to autoconfigure the CPU port. It's odd for
        // these not to exist, but legal, in which case we make a default.
        let port_id = PortId::Internal(InternalPort::try_from(0).unwrap());
        let default_cpu_link_params = || LinkCreate {
            lane: None,
            speed: PortSpeed::Speed100G,
            fec: Some(PortFec::None),
            autoneg: true,
            kr: true,
            tx_eq: None,
        };
        let params = match &autoconfig_links {
            Some(links) => links
                .get(&port_id)
                .cloned()
                .unwrap_or_else(default_cpu_link_params),
            None => default_cpu_link_params(),
        };

        // TODO-robustness: There really should not be anyone else on our
        // segment other than the SP, but it's not possible to rule it out. We
        // may need to detect whether there is a collision here, and retry
        // creating a MAC until that's not the case.
        let temp_mac = BaseMac::Temporary(MacAddr::random_oxide());
        debug!(self.log, "created temporary random MAC"; "mac" => %temp_mac);
        {
            let mut mgr = self.mac_mgmt.lock().unwrap();
            assert_eq!(mgr.set_base_mac(temp_mac)?, None);
        }
        crate::table::port_mac::reset(self)?;

        // Create the link on the CPU port.
        let link_id = self.create_link(port_id, &params)?;
        debug!(self.log, "created temporary CPU port link"; "linkid" => %link_id);

        // Enable the link.
        self.set_link_enabled(port_id, link_id, true)?;
        debug!(self.log, "enabled temporary CPU port link");

        // Ask the SP for our base MAC address.
        let base_mac = self.fetch_base_mac_from_sp().await;

        slog::info!(
            self.log,
            "resetting base MAC address";
            "old" => %temp_mac,
            "new" => %base_mac,
        );

        // Release the old mac address before updating the base mac
        self.free_mac_address(temp_mac.mac_addr());

        // update the base mac address in the manager.
        //
        // It is now permanent, since we've fetched it from the SP. No further
        // calls to set it will succeed.
        {
            let mut mgr = self.mac_mgmt.lock().unwrap();
            let new = BaseMac::Permanent(base_mac);
            assert_eq!(mgr.set_base_mac(new)?, Some(temp_mac));
        }

        // Finally update the mac address for this link in the asic
        let cpu_mac = self
            .allocate_mac_address(port_id, link_id)
            .expect("Expected a MAC for the internal CPU link");
        self.set_link_mac_address(port_id, link_id, cpu_mac)?;

        Ok(true)
    }
}

#[cfg(not(feature = "tofino_asic"))]
impl Switch {
    /// Assign a permanent but random base MAC address on non-Tofino systems.
    pub async fn set_base_mac_address(
        &self,
        _autoconfig_links: &Option<crate::AutoconfiguredLinks>,
    ) -> anyhow::Result<bool> {
        // For non-ASIC builds, we just use a random MAC as our base address.
        let base_mac = BaseMac::Permanent(MacAddr::random_oxide());
        debug!(
            self.log,
            "assigning random base MAC address";
            "mac" => %base_mac
        );
        let mut mgr = self.mac_mgmt.lock().unwrap();
        mgr.set_base_mac(base_mac)?;
        Ok(false)
    }
}

// Generate the offset from a base MAC address, for the provided switch port and
// link.
//
// If the link_id falls out of the range for which a mac address has been
// reserved.reserved.
fn mac_offset(port_id: PortId, link_id: LinkId) -> Option<u16> {
    let link_id: u16 = link_id.into();
    match port_id {
        PortId::Internal(_) => {
            if link_id < LINKS_PER_INTERNAL {
                Some(MAC_OFFSET_INTERNAL + link_id)
            } else {
                None
            }
        }
        PortId::Rear(rear) => {
            let port_id: u16 = rear.as_u8().into();
            if link_id < LINKS_PER_REAR {
                Some(MAC_OFFSET_REAR + port_id * LINKS_PER_REAR + link_id)
            } else {
                None
            }
        }
        PortId::Qsfp(qsfp) => {
            let port_id: u16 = qsfp.as_u8().into();
            if link_id < LINKS_PER_QSFP {
                Some(MAC_OFFSET_QSFP + port_id * LINKS_PER_QSFP + link_id)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mac_offset;
    use crate::link::LinkId;
    use crate::macaddrs::BaseMac;
    use crate::macaddrs::MacManagement;
    use common::network::MacAddr;
    use common::ports::InternalPort;
    use common::ports::PortId;
    use common::ports::QsfpPort;
    use common::ports::RearPort;
    use slog::Drain;
    use std::convert::TryFrom;

    #[test]
    fn test_parse_port_id() {
        assert_eq!(
            PortId::Rear(RearPort::try_from(3).unwrap()),
            "rear3".parse().unwrap()
        );
        assert_eq!(
            PortId::Rear(RearPort::try_from(3).unwrap()),
            "REAR3".parse().unwrap()
        );
        assert_eq!(
            PortId::Qsfp(QsfpPort::try_from(3).unwrap()),
            "qsfp3".parse().unwrap()
        );
        assert_eq!(
            PortId::Qsfp(QsfpPort::try_from(3).unwrap()),
            "QSFP3".parse().unwrap()
        );
        assert_eq!(
            PortId::Internal(InternalPort::try_from(0).unwrap()),
            "int0".parse().unwrap()
        );

        assert!("int".parse::<PortId>().is_err());
        assert!("cpu0".parse::<PortId>().is_err());
        assert!("rear256".parse::<PortId>().is_err());
        assert!("foo".parse::<PortId>().is_err());
        assert!("rear".parse::<PortId>().is_err());
        assert!("rear-1".parse::<PortId>().is_err());
    }

    #[test]
    fn test_mac_offset() {
        let port_id = PortId::Internal(InternalPort::try_from(0).unwrap());
        let link_id = LinkId(0);
        assert_eq!(mac_offset(port_id, link_id), Some(0));

        let port_id = PortId::Internal(InternalPort::try_from(0).unwrap());
        let link_id = LinkId(1);
        assert_eq!(mac_offset(port_id, link_id), None);

        let port_id = PortId::Rear(RearPort::try_from(0).unwrap());
        let link_id = LinkId(0);
        assert_eq!(mac_offset(port_id, link_id), Some(1));

        let port_id = PortId::Rear(RearPort::try_from(0).unwrap());
        let link_id = LinkId(1);
        assert_eq!(mac_offset(port_id, link_id), None);

        let port_id = PortId::Rear(RearPort::try_from(1).unwrap());
        let link_id = LinkId(0);
        assert_eq!(mac_offset(port_id, link_id), Some(2));

        let port_id = PortId::Qsfp(QsfpPort::try_from(0).unwrap());
        let link_id = LinkId(0);
        assert_eq!(mac_offset(port_id, link_id), Some(1 + 32));

        let port_id = PortId::Qsfp(QsfpPort::try_from(0).unwrap());
        let link_id = LinkId(1);
        assert_eq!(mac_offset(port_id, link_id), Some(1 + 32 + 1));

        let port_id = PortId::Qsfp(QsfpPort::try_from(1).unwrap());
        let link_id = LinkId(0);
        assert_eq!(mac_offset(port_id, link_id), Some(1 + 32 + 4));

        let port_id = PortId::Qsfp(QsfpPort::try_from(0).unwrap());
        let link_id = LinkId(4);
        assert_eq!(mac_offset(port_id, link_id), None);
    }

    fn test_log() -> slog::Logger {
        let dec =
            slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(dec).build().fuse();
        slog::Logger::root(drain, slog::o!())
    }

    #[test]
    fn test_mac_management_set_base_mac_permanent_once() {
        let mut mgr = MacManagement::new(&test_log());
        let temp = BaseMac::Temporary(MacAddr::random_oxide());
        let old = mgr.set_base_mac(temp).expect(
            "Should be able to set base MAC as temporary when none exists",
        );
        assert_eq!(old, None, "Old base mac address should not exist");
        assert_eq!(mgr.base_mac, Some(temp));

        // We should not be able to set it temp twice.
        let new_temp = BaseMac::Temporary(MacAddr::random_oxide());
        mgr
            .set_base_mac(new_temp)
            .expect_err("Should not be able to set base MAC as temporary when a temporary one exists");

        // We should be able to set it permanent when we have a temp address.
        let perm = BaseMac::Permanent(MacAddr::random_oxide());
        let old = mgr
            .set_base_mac(perm)
            .expect("Should be able to set base MAC as permanent when a temporary one exists");
        assert_eq!(old, Some(temp));

        // We should not be able to set it to anything again.
        let new_perm = BaseMac::Permanent(MacAddr::random_oxide());
        mgr.set_base_mac(new_perm).expect_err(
            "We should not be able to set the base MAC \
                to a new permanent one, after it's been set permanent once",
        );

        // We should also be able to set it right to permanent, but not again.
        let mut mgr = MacManagement::new(&test_log());
        let perm = BaseMac::Permanent(MacAddr::random_oxide());
        let old = mgr.set_base_mac(perm).expect(
            "Should be able to set base MAC as permanent when none exists",
        );
        assert_eq!(old, None);
    }

    #[test]
    fn test_only_alloc_cpu_link_mac_when_temporary() {
        let mut mgr = MacManagement::new(&test_log());
        let link_id = LinkId(0);
        let port_id = InternalPort::new(0).unwrap().into();
        assert!(
            mgr.allocate_mac_address(port_id, link_id).is_none(),
            "Should not be able to alloc any MAC when there is no base"
        );

        let temp = BaseMac::Temporary(MacAddr::random_oxide());
        let old = mgr.set_base_mac(temp).expect(
            "Should be able to set base MAC as temporary when none exists",
        );
        assert_eq!(old, None);
        let mac = mgr
            .allocate_mac_address(
                port_id,
                link_id,
            )
            .expect("Should be able to alloc MAC for CPU port when we have a temporary base");
        assert_eq!(mac, temp.mac_addr());

        // Can only allocate a MAC for other ports once the base has been set to
        // permanent.
        let rear_port = RearPort::new(0).unwrap().into();
        assert_eq!(
            mgr.allocate_mac_address(rear_port, link_id),
            None,
            "Should not be able to alloc MAC for rear port when we have a temporary base",
        );
        let qsfp_port = QsfpPort::new(0).unwrap().into();
        assert_eq!(
            mgr.allocate_mac_address(qsfp_port, link_id),
            None,
            "Should not be able to alloc MAC for QSFP port when we have a temporary base",
        );

        // Now anything is possible, once we free the existing temporary MAC
        // allocated above.
        mgr.free_mac_address(temp.mac_addr());
        let perm = BaseMac::Permanent(MacAddr::random_oxide());
        let old = mgr.set_base_mac(perm).expect(
            "Should be able to set base MAC as permanent when a temporary one exists",
        );
        assert_eq!(old, Some(temp));
        mgr
            .allocate_mac_address(
                rear_port,
                link_id,
            )
            .expect("Should be able to alloc MAC for rear port when we have a temporary base");
        mgr
            .allocate_mac_address(
                qsfp_port,
                link_id,
            )
            .expect("Should be able to alloc MAC for QSFP port when we have a temporary base");
    }
}
