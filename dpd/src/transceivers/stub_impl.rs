// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Stub implementations of switch methods related to transceivers.
//!
//! Note that most methods in the `tofino_impl` module do _not_ have
//! counterparts here. Only those which are required at the higher levels of
//! `dpd`, such as in the API endpoint handlers themselves, should have stub
//! implementations.

use crate::types::DpdError;
use crate::types::DpdResult;
use crate::Switch;
use common::ports::QsfpPort;
use tokio::sync::RwLockReadGuard;
use transceiver_controller::Controller;
use transceiver_controller::Datapath;
use transceiver_controller::Monitors;
use transceiver_controller::PowerState;

impl Switch {
    pub async fn reset_transceiver(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<()> {
        Err(DpdError::MissingTransceiver { qsfp_port })
    }

    pub async fn set_transceiver_power(
        &self,
        qsfp_port: QsfpPort,
        _: PowerState,
    ) -> DpdResult<()> {
        Err(DpdError::MissingTransceiver { qsfp_port })
    }

    pub async fn transceiver_power(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<PowerState> {
        Err(DpdError::MissingTransceiver { qsfp_port })
    }

    pub async fn transceiver_monitors(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<Monitors> {
        Err(DpdError::MissingTransceiver { qsfp_port })
    }

    pub async fn transceiver_datapath(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<Datapath> {
        Err(DpdError::MissingTransceiver { qsfp_port })
    }

    pub async fn transceiver_controller(
        &self,
    ) -> DpdResult<RwLockReadGuard<Controller>> {
        Err(DpdError::NoTransceiverController)
    }
}
