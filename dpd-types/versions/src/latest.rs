// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Re-exports of the latest versions of all published types.

pub mod arp {
    pub use crate::v1::arp::ArpEntry;
    pub use crate::v1::arp::ArpToken;
    pub use crate::v1::arp::Ipv4ArpParam;
    pub use crate::v1::arp::Ipv4Token;
    pub use crate::v1::arp::Ipv6ArpParam;
    pub use crate::v1::arp::Ipv6Token;
}

pub mod attached_subnet {
    pub use crate::v3::attached_subnet::AttachedSubnetEntry;
}

pub mod counters {
    pub use crate::v1::counters::CounterData;
    pub use crate::v1::counters::CounterPath;
    pub use crate::v1::counters::CounterSync;
    pub use crate::v1::counters::FecRSCounters;
    pub use crate::v1::counters::LinkFecRSCounters;
    pub use crate::v1::counters::LinkPcsCounters;
    pub use crate::v1::counters::LinkRMonCounters;
    pub use crate::v1::counters::LinkRMonCountersAll;
    pub use crate::v1::counters::PcsCounters;
    pub use crate::v1::counters::RMonCounters;
    pub use crate::v1::counters::RMonCountersAll;
}

pub mod fault {
    pub use crate::v1::fault::Fault;
    pub use crate::v1::fault::FaultCondition;
}

pub mod link {
    pub use crate::v1::link::LinkEvent;
    pub use crate::v1::link::LinkFilter;
    pub use crate::v1::link::LinkFsmCounter;
    pub use crate::v1::link::LinkFsmCounters;
    pub use crate::v1::link::LinkId;
    pub use crate::v1::link::LinkIpv4Path;
    pub use crate::v1::link::LinkIpv6Path;
    pub use crate::v1::link::LinkPath;
    pub use crate::v1::link::LinkState;
    pub use crate::v1::link::LinkUpCounter;
    pub use crate::v1::link::TfportData;

    pub use crate::v11::link::LinkHistory;

    pub use crate::v12::link::LinkView;
    pub use crate::v12::link::MsDuration;

    pub use crate::v13::link::LinkCreate;
}

pub mod loopback {
    pub use crate::v1::loopback::LoopbackIpv4Path;
    pub use crate::v1::loopback::LoopbackIpv6Path;
}

pub mod mcast {
    pub use crate::v1::mcast::Direction;
    pub use crate::v1::mcast::ExternalForwarding;
    pub use crate::v1::mcast::InternalForwarding;
    pub use crate::v1::mcast::MulticastGroupId;
    pub use crate::v1::mcast::MulticastGroupIdParam;
    pub use crate::v1::mcast::MulticastGroupIpParam;
    pub use crate::v1::mcast::MulticastGroupMember;

    pub use crate::v7::mcast::IpSrc;
    pub use crate::v7::mcast::MulticastGroupCreateExternalEntry;

    pub use crate::v8::mcast::Error;
    pub use crate::v8::mcast::MulticastGroupCreateUnderlayEntry;
    pub use crate::v8::mcast::MulticastGroupExternalResponse;
    pub use crate::v8::mcast::MulticastGroupResponse;
    pub use crate::v8::mcast::MulticastGroupTagQuery;
    pub use crate::v8::mcast::MulticastGroupUnderlayResponse;
    pub use crate::v8::mcast::MulticastGroupUpdateExternalEntry;
    pub use crate::v8::mcast::MulticastGroupUpdateUnderlayEntry;
    pub use crate::v8::mcast::MulticastTag;
    pub use crate::v8::mcast::MulticastTagPath;
    pub use crate::v8::mcast::MulticastUnderlayGroupIpParam;
    pub use crate::v8::mcast::UnderlayMulticastIpv6;

    pub use crate::impls::mcast::MAX_TAG_LENGTH;
    pub use crate::impls::mcast::MulticastTagParseError;
}

pub mod misc {
    pub use crate::v1::misc::BuildInfo;
    pub use crate::v1::misc::TagPath;
}

pub mod nat {
    pub use crate::v1::nat::Ipv4Nat;
    pub use crate::v1::nat::Ipv6Nat;
    pub use crate::v1::nat::NatIpv4Path;
    pub use crate::v1::nat::NatIpv4PortPath;
    pub use crate::v1::nat::NatIpv4RangePath;
    pub use crate::v1::nat::NatIpv6Path;
    pub use crate::v1::nat::NatIpv6PortPath;
    pub use crate::v1::nat::NatIpv6RangePath;
    pub use crate::v1::nat::NatToken;
}

pub mod network {
    pub use crate::v1::network::MacAddr;
    pub use crate::v1::network::MacError;
    pub use crate::v1::network::NatTarget;
    pub use crate::v1::network::Vni;

    pub use crate::v3::network::InstanceTarget;
}

pub mod oxstats {
    pub use crate::v1::oxstats::SledIdentifiers;

    pub use crate::v10::oxstats::OximeterConfig;
    pub use crate::v10::oxstats::OximeterMetadata;
}

pub mod port {
    pub use crate::v1::port::FreeChannels;
    pub use crate::v1::port::InternalPort;
    pub use crate::v1::port::Ipv4Entry;
    pub use crate::v1::port::Ipv6Entry;
    pub use crate::v1::port::PORT_COUNT_INTERNAL;
    pub use crate::v1::port::PORT_COUNT_QSFP;
    pub use crate::v1::port::PORT_COUNT_REAR;
    pub use crate::v1::port::PortCreateParams;
    pub use crate::v1::port::PortFec;
    pub use crate::v1::port::PortId;
    pub use crate::v1::port::PortIdPathParams;
    pub use crate::v1::port::PortIpv4Path;
    pub use crate::v1::port::PortIpv6Path;
    pub use crate::v1::port::PortMedia;
    pub use crate::v1::port::PortSettingsTag;
    pub use crate::v1::port::PortSpeed;
    pub use crate::v1::port::PortToken;

    pub use crate::v1::port::QsfpPort;
    pub use crate::v1::port::RearPort;

    pub use crate::v12::port::PortPrbsMode;

    pub use crate::v13::port::LinkSettings;
    pub use crate::v13::port::PortSettings;

    pub use crate::v14::txeq::TxEq;
    pub use crate::v14::txeq::TxEqConfig;
    pub use crate::v14::txeq::TxEqSwHw;
}

pub mod port_map {
    pub use crate::v1::port_map::BackplaneCableLeg;
    pub use crate::v1::port_map::BackplaneLink;
    pub use crate::v1::port_map::Error;
    pub use crate::v1::port_map::SIDECAR_REV_AB_BACKPLANE_MAP;
    pub use crate::v1::port_map::SidecarCableLeg;
    pub use crate::v1::port_map::SidecarConnector;
}

pub mod route {
    pub use crate::v1::route::Ipv4Route;
    pub use crate::v1::route::Ipv4RouteToken;
    pub use crate::v1::route::Ipv6Route;
    pub use crate::v1::route::Ipv6RouteToken;
    pub use crate::v1::route::Ipv6RouteUpdate;
    pub use crate::v1::route::Ipv6Routes;
    pub use crate::v1::route::RoutePathV4;
    pub use crate::v1::route::RoutePathV6;
    pub use crate::v1::route::RouteSettingsV4;
    pub use crate::v1::route::RouteSettingsV6;
    pub use crate::v1::route::RouteTargetIpv6Path;

    pub use crate::v3::route::AttachedSubnetToken;
    pub use crate::v3::route::SubnetPath;

    pub use crate::v4::route::Ipv4Routes;
    pub use crate::v4::route::Route;
    pub use crate::v4::route::RouteTarget;

    pub use crate::v6::route::Ipv4RouteUpdate;
    pub use crate::v6::route::RouteTargetIpv4Path;
}

pub mod serdes {
    pub use crate::v1::serdes::AnLtStatus;
    pub use crate::v1::serdes::AnStatus;
    pub use crate::v1::serdes::Ber;
    pub use crate::v1::serdes::DfeAdaptationState;
    pub use crate::v1::serdes::EncSpeed;
    pub use crate::v1::serdes::LaneEncoding;
    pub use crate::v1::serdes::LaneMap;
    pub use crate::v1::serdes::LaneStatus;
    pub use crate::v1::serdes::LpPages;
    pub use crate::v1::serdes::LtStatus;
    pub use crate::v1::serdes::Polarity;
    pub use crate::v1::serdes::RxSigInfo;
    pub use crate::v1::serdes::SerdesEye;
}

pub mod snapshot {
    pub use crate::v9::snapshot::SnapshotCreate;
    pub use crate::v9::snapshot::SnapshotDirection;
    pub use crate::v9::snapshot::SnapshotFieldScope;
    pub use crate::v9::snapshot::SnapshotFieldValue;
    pub use crate::v9::snapshot::SnapshotResult;
    pub use crate::v9::snapshot::SnapshotScopeRequest;
    pub use crate::v9::snapshot::SnapshotStageResult;
    pub use crate::v9::snapshot::SnapshotTableResult;
    pub use crate::v9::snapshot::SnapshotTrigger;
    pub use crate::v9::snapshot::TableDumpOptions;
}

pub mod switch_identifiers {
    pub use crate::v10::switch_identifiers::ChipRevision;
    pub use crate::v10::switch_identifiers::DisabledFeatures;
    pub use crate::v10::switch_identifiers::FrequencySettings;
    pub use crate::v10::switch_identifiers::FuseData;
    pub use crate::v10::switch_identifiers::ManufacturingData;
    pub use crate::v10::switch_identifiers::PartInfo;
    pub use crate::v10::switch_identifiers::SwitchIdentifiers;
}

pub mod switch_port {
    pub use crate::v1::switch_port::Led;
    pub use crate::v1::switch_port::LedPolicy;
    pub use crate::v1::switch_port::LedState;
    pub use crate::v1::switch_port::ManagementMode;
    pub use crate::v1::switch_port::SwitchPortView;
}

pub mod table {
    pub use crate::v1::table::Table;
    pub use crate::v1::table::TableCounterEntry;
    pub use crate::v1::table::TableDumpEntry;
    pub use crate::v1::table::TableDumpKeyField;
    pub use crate::v1::table::TableDumpRequest;
    pub use crate::v1::table::TableDumpResult;
    pub use crate::v1::table::TableEntry;
    pub use crate::v1::table::TableParam;

    pub use crate::impls::table::TableEntryAction;
    pub use crate::impls::table::TableEntryKey;
}

pub mod transceivers {
    pub use crate::v1::transceivers::ActiveCableMediaInterfaceId;
    pub use crate::v1::transceivers::ApplicationDescriptor;
    pub use crate::v1::transceivers::Aux1Monitor;
    pub use crate::v1::transceivers::Aux2Monitor;
    pub use crate::v1::transceivers::Aux3Monitor;
    pub use crate::v1::transceivers::AuxMonitors;
    pub use crate::v1::transceivers::BaseTMediaInterfaceId;
    pub use crate::v1::transceivers::CmisDatapath;
    pub use crate::v1::transceivers::CmisDatapathState;
    pub use crate::v1::transceivers::CmisLaneStatus;
    pub use crate::v1::transceivers::ConnectorType;
    pub use crate::v1::transceivers::Datapath;
    pub use crate::v1::transceivers::ElectricalMode;
    pub use crate::v1::transceivers::EthernetComplianceCode;
    pub use crate::v1::transceivers::ExtendedSpecificationComplianceCode;
    pub use crate::v1::transceivers::FaultReason;
    pub use crate::v1::transceivers::HostElectricalInterfaceId;
    pub use crate::v1::transceivers::Identifier;
    pub use crate::v1::transceivers::LanePolarity;
    pub use crate::v1::transceivers::MediaInterfaceId;
    pub use crate::v1::transceivers::MmfMediaInterfaceId;
    pub use crate::v1::transceivers::Monitors;
    pub use crate::v1::transceivers::Oui;
    pub use crate::v1::transceivers::OutputStatus;
    pub use crate::v1::transceivers::PassiveCopperMediaInterfaceId;
    pub use crate::v1::transceivers::PowerMode;
    pub use crate::v1::transceivers::PowerState;
    pub use crate::v1::transceivers::QsfpDevice;
    pub use crate::v1::transceivers::ReceiverPower;
    pub use crate::v1::transceivers::Sff8636Datapath;
    pub use crate::v1::transceivers::SffComplianceCode;
    pub use crate::v1::transceivers::SmfMediaInterfaceId;
    pub use crate::v1::transceivers::Transceiver;
    pub use crate::v1::transceivers::TransceiverInfo;
    pub use crate::v1::transceivers::Vendor;
    pub use crate::v1::transceivers::VendorInfo;
}
