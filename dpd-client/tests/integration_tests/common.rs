// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use std::{fmt, thread};

use anyhow::anyhow;
use oxnet::IpNet;
use oxnet::Ipv4Net;
use oxnet::Ipv6Net;
use slog::Drain;

use ::common::network::MacAddr;
use ::common::ports::PortId;
use dpd_client::types;
use dpd_client::Client;
use dpd_client::ClientState;
use packet::arp;
use packet::eth;
use packet::icmp;
use packet::ipv4;
use packet::ipv6;
use packet::sidecar;
use packet::Endpoint;
use packet::Packet;

const SHOW_VERBOSE: u8 = 0x01;
const SHOW_HEX: u8 = 0x02;

// Timeout set on `Pcap` objects.
//
// This is used as the "buffer timeout", which is the duration libpcap buffers
// packets before notifying us that any are ready.
const TEST_PCAP_TIMEOUT_MS: i32 = 1;

// Physical port number
#[derive(Clone, Copy, PartialOrd, Ord, Hash, PartialEq, Eq)]
pub struct PhysPort(pub u16);
pub const NO_PORT: PhysPort = PhysPort(0xffff);

// On real hardware the "service port" is the PCI port, which doesn't have a
// real physical port - it's just a collection of ringbufs in PCI space.  On the
// model, we have "physical port" 33 wired to carry the traffic for "tofino
// port" 0, which is the PCI port on Tofino 2.
pub const SERVICE_PORT: PhysPort = PhysPort(33);

impl fmt::Display for PhysPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PhysPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Used for indexing into the Switch ports list
impl std::convert::From<PhysPort> for usize {
    fn from(p: PhysPort) -> Self {
        p.0 as _
    }
}

// The test switch object storing all test state.
lazy_static::lazy_static! {
    static ref TEST_SWITCH: parking_lot::Mutex<Switch> = {
        let host = std::env::var("DENDRITE_TEST_HOST")
            .unwrap_or_else(|_| String::from("localhost"));
        let port = std::env::var("DENDRITE_TEST_PORT")
            .map(|p| p.parse().expect("Invalid port"))
            .unwrap_or_else(|_| dpd_client::default_port());
        let use_network = !std::env::var("DENDRITE_TEST_API_ONLY")
            .map(|p| p.parse().expect("Invalid bool"))
            .unwrap_or(false);
        let verbosity = std::env::var("DENDRITE_TEST_VERBOSITY")
            .map(|p| p.parse().expect("Invalid verbosity"))
            .unwrap_or(0);
        let millis = std::env::var("DENDRITE_TEST_TIMEOUT")
            .map(|p| p.parse().expect("Invalid duration"))
            .unwrap_or(500);

        parking_lot::Mutex::new(Switch::new(host, port, use_network, verbosity, Duration::from_millis(millis)))
    };
}
static SWITCH_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Return a reference to the `Switch` test state object.
///
/// The test state on the `dpd` server will be completely cleared when the object is returned.
pub async fn get_switch() -> parking_lot::MutexGuard<'static, Switch> {
    let mut sw = TEST_SWITCH.lock();
    if let Ok(false) = SWITCH_INITIALIZED.compare_exchange(
        false,
        true,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        sw.init().await.unwrap();
    }
    sw.client.reset_all().await.unwrap();
    sw.reset_all_mac_addrs().await;
    sw
}

pub type TestResult = Result<(), anyhow::Error>;

pub struct TestPacket {
    pub port: PhysPort,
    pub packet: Arc<packet::Packet>,
}

fn dump_hex(a: &[u8]) {
    const CHUNK_SIZE: usize = 16;
    let mut off = 0;

    for line in a.chunks(CHUNK_SIZE) {
        let mut hex = String::new();
        let mut txt = String::new();
        for i in 0..CHUNK_SIZE {
            if i % 2 == 0 {
                hex.push(' ');
            }
            if i < line.len() {
                let _ = write!(hex, "{:02x}", line[i]);

                let c = line[i] as char;
                txt.push(match c.is_ascii_control() {
                    true => '.',
                    false => c,
                });
            } else {
                hex.push_str("  ");
            }
        }
        println!("{off:04x}:{hex} {txt}");
        off += CHUNK_SIZE;
    }
}

impl TestPacket {
    pub fn show(&self, verbosity: u8) {
        if verbosity & SHOW_VERBOSE == 0 {
            println!("port: {}: {:}", self.port, self.packet);
        } else {
            println!("port: {}: {:?}", self.port, self.packet);
        }
        if verbosity & SHOW_HEX != 0 {
            let data = self.packet.deparse().unwrap();
            dump_hex(&data);
        }
    }
}

impl PartialEq for TestPacket {
    fn eq(&self, other: &Self) -> bool {
        self.port == other.port && self.packet == other.packet
    }
}

impl fmt::Debug for TestPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port: {}  pkt: {:?}", self.port, self.packet)
    }
}

struct Port {
    // The switch port in which the link appears.
    port_id: PortId,
    // The ID of the link within the port.
    link_id: types::LinkId,
    // Tofino's internal ID for the port.
    tofino_port: u16,
    // Linux Ethernet device carrying ports traffic.
    //
    // If None, then this has no device. Any packet captures will reflect all interfaces.
    veth: Option<String>,
    // Handle the a `libpcap` device, for capturing and testing packets.
    pcap_out: Arc<pcap::Pcap>,
    // The MAC address for this port.
    //
    // This is initially None on startup, and filled when we start by asking
    // Dendrite.
    mac: Option<MacAddr>,
}

impl Port {
    pub fn new(
        port: u16,
        port_id: PortId,
        veth_in: Option<&str>,
        _veth_out: Option<&str>,
    ) -> Port {
        // The model nominally uses different veth devices for inbound and outbound
        // traffic, but in practice it doesn't seem to matter which one you use.  To
        // keep things simple, we just use the 'in' veth for traffic in both
        // directions.  If we start losing packets after a simulator upgrade, this
        // would be a good place to look.
        let mut pcap_out = pcap::create(&veth_in).unwrap();
        pcap_out.set_timeout(TEST_PCAP_TIMEOUT_MS).unwrap();
        pcap_out.activate().unwrap();
        Port {
            port_id,
            link_id: types::LinkId(0),
            tofino_port: port,
            veth: veth_in.map(String::from),
            pcap_out: Arc::new(pcap_out),
            mac: None,
        }
    }
}

pub struct Switch {
    pub client: Client,
    ports: Vec<Option<Port>>,
    packets: Arc<Mutex<Vec<TestPacket>>>,

    // If true, run tests that require networking. If false, only tests of the
    // `dpd` Dropshot API are run.
    network: bool,

    // This belongs to the test framework, not the switch.  It doesn't belong
    // here, but we're hitching a ride rather than complication each test case
    // call.
    verbosity: u8,

    // Time that each test waits for its expected packets.
    packet_timeout: Duration,
}

impl Switch {
    fn new(
        ctrl_host: String,
        ctrl_port: u16,
        network: bool,
        verbosity: u8,
        packet_timeout: Duration,
    ) -> Switch {
        let decorator =
            slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let log = slog::Logger::root(drain, slog::o!());
        let client_state = ClientState {
            tag: String::from("test"),
            log,
        };
        let client = Client::new(
            &format!("http://{ctrl_host}:{ctrl_port}"),
            client_state,
        );

        // The following port definitions are based on the FrontPanel->DevPort
        // mappings we get from the Tofino model.  The ports that have attached
        // veth devices, as well as the names of those devices, come from the
        // tools/ports_tof2.json file.  If the model is launched using a
        // different port layout description, most of the tests will fail.
        //
        // The mapping from the ASIC port ID to the `dpd` PortId is derived from
        // asking the SDE as well. Specifically, we create a link on each of the
        // rear ports, and then use `swadm` to return the ASIC ID for each link.
        let ports = vec![
            None,
            Some(Port::new(
                8,
                PortId::try_from("rear29").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                16,
                PortId::try_from("rear31").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                24,
                PortId::try_from("rear25").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                32,
                PortId::try_from("rear27").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                40,
                PortId::try_from("rear21").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                48,
                PortId::try_from("rear23").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                56,
                PortId::try_from("rear17").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                64,
                PortId::try_from("rear19").unwrap(),
                Some("veth0"),
                Some("veth1"),
            )),
            Some(Port::new(
                136,
                PortId::try_from("rear11").unwrap(),
                Some("veth2"),
                Some("veth3"),
            )),
            Some(Port::new(
                144,
                PortId::try_from("rear9").unwrap(),
                Some("veth4"),
                Some("veth5"),
            )),
            Some(Port::new(
                152,
                PortId::try_from("rear15").unwrap(),
                Some("veth6"),
                Some("veth7"),
            )),
            Some(Port::new(
                160,
                PortId::try_from("rear13").unwrap(),
                Some("veth8"),
                Some("veth9"),
            )),
            Some(Port::new(
                168,
                PortId::try_from("rear3").unwrap(),
                Some("veth10"),
                Some("veth11"),
            )),
            Some(Port::new(
                176,
                PortId::try_from("rear1").unwrap(),
                Some("veth12"),
                Some("veth13"),
            )),
            Some(Port::new(
                184,
                PortId::try_from("rear7").unwrap(),
                Some("veth14"),
                Some("veth15"),
            )),
            Some(Port::new(
                192,
                PortId::try_from("rear5").unwrap(),
                Some("veth16"),
                Some("veth17"),
            )),
            Some(Port::new(
                264,
                PortId::try_from("rear28").unwrap(),
                Some("veth18"),
                Some("veth19"),
            )),
            Some(Port::new(
                272,
                PortId::try_from("rear30").unwrap(),
                Some("veth20"),
                Some("veth21"),
            )),
            Some(Port::new(
                280,
                PortId::try_from("rear24").unwrap(),
                Some("veth22"),
                Some("veth23"),
            )),
            Some(Port::new(
                288,
                PortId::try_from("rear26").unwrap(),
                Some("veth24"),
                Some("veth25"),
            )),
            Some(Port::new(
                296,
                PortId::try_from("rear20").unwrap(),
                Some("veth26"),
                Some("veth27"),
            )),
            Some(Port::new(
                304,
                PortId::try_from("rear22").unwrap(),
                Some("veth28"),
                Some("veth29"),
            )),
            Some(Port::new(
                312,
                PortId::try_from("rear16").unwrap(),
                Some("veth30"),
                Some("veth31"),
            )),
            Some(Port::new(
                320,
                PortId::try_from("rear18").unwrap(),
                Some("veth32"),
                Some("veth33"),
            )),
            Some(Port::new(
                392,
                PortId::try_from("rear10").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                400,
                PortId::try_from("rear8").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                408,
                PortId::try_from("rear14").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                416,
                PortId::try_from("rear12").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                424,
                PortId::try_from("rear2").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                432,
                PortId::try_from("rear0").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                440,
                PortId::try_from("rear6").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                448,
                PortId::try_from("rear4").unwrap(),
                None,
                None,
            )),
            Some(Port::new(
                0,
                PortId::try_from("int0").unwrap(),
                Some("veth250"),
                Some("veth251"),
            )),
        ];

        Switch {
            client,
            ports,
            packets: Arc::new(Mutex::new(Vec::new())),
            network,
            verbosity,
            packet_timeout,
        }
    }

    // Reset all MAC addresses to those we've received from `dpd` during the call
    // to `Self::init()`.
    async fn reset_all_mac_addrs(&self) {
        for port in self.ports.iter().flatten() {
            if let Some(mac) = port.mac {
                self.client
                    .link_mac_set(&port.port_id, &port.link_id, &mac.into())
                    .await
                    .unwrap()
                    .into_inner();
            }
        }
    }

    async fn init(&mut self) -> Result<(), String> {
        for port in self.ports.iter_mut().flatten() {
            match self.client.link_mac_get(&port.port_id, &port.link_id).await {
                Ok(m) => port.mac = Some(m.into_inner().into()),
                Err(e) => {
                    panic!(
                        "failed to get mac for port {}/{}: {:?}",
                        port.port_id.to_string(),
                        *port.link_id,
                        e,
                    )
                }
            }
        }

        // Create a thread that takes packets from every "port listener" and
        // places them onto our own packet queue.
        let (tx, rx) = mpsc::channel();
        let packet_queue = self.packets.clone();
        if self.network {
            let _ = std::thread::spawn(move || {
                Switch::port_collector(packet_queue, rx)
            });
        }

        // Spawn a thread that listens for packets on a `Pcap` device for each
        // port, and pushes them onto the `mpsc` channel.
        for port_num in 0..self.ports.len() {
            if let Some(port) = self.ports[port_num].as_ref() {
                let tx_clone = tx.clone();
                if self.network && port.veth.is_some() {
                    let p = self.ports[port_num].as_ref().unwrap();

                    let mut hdl = pcap::create(&p.veth.as_deref()).unwrap();
                    hdl.set_timeout(TEST_PCAP_TIMEOUT_MS).unwrap();
                    hdl.activate().unwrap();

                    let _ = std::thread::spawn(move || {
                        Switch::port_listener(
                            hdl,
                            PhysPort(port_num as u16),
                            tx_clone,
                        );
                    });
                }
            }
        }
        Ok(())
    }

    pub fn tofino_port(&self, phys_port: PhysPort) -> u16 {
        let idx: usize = phys_port.into();
        if phys_port == NO_PORT {
            0
        } else if let Some(port) = &self.ports[idx] {
            port.tofino_port
        } else {
            panic!("request for missing port: {phys_port}");
        }
    }

    /// Return the PortId and LinkId for all the link associated with the
    /// physical switch port.
    pub fn link_id(
        &self,
        phys_port: PhysPort,
    ) -> Option<(PortId, types::LinkId)> {
        let idx: usize = phys_port.into();
        if phys_port == NO_PORT {
            None
        } else if let Some(port) = &self.ports[idx] {
            Some((port.port_id.clone(), port.link_id.clone()))
        } else {
            panic!("request for missing port: {phys_port}");
        }
    }

    /// Return an iterator over all links.
    pub fn iter_links(
        &self,
    ) -> impl Iterator<Item = (PortId, types::LinkId)> + '_ {
        self.ports.iter().filter(|x| x.is_some()).map(|p| {
            let Some(p) = p else {
                unreachable!("Filtered to only Some(_)");
            };
            (p.port_id.clone(), p.link_id.clone())
        })
    }

    fn port_collector(
        packets: Arc<Mutex<Vec<TestPacket>>>,
        rx: mpsc::Receiver<TestPacket>,
    ) {
        loop {
            match rx.recv() {
                Err(e) => panic!("receive failed: {e}"),
                Ok(packet) => {
                    packets.lock().unwrap().push(packet);
                }
            }
        }
    }

    fn port_listener(
        hdl: pcap::Pcap,
        port: PhysPort,
        tx: mpsc::Sender<TestPacket>,
    ) {
        loop {
            match hdl.next_owned() {
                pcap::Ternary::None => break,
                pcap::Ternary::Err(e) => {
                    println!("port {port} got pcap error: {e}");
                    break;
                }
                pcap::Ternary::Ok(data) => {
                    let packet = packet::Packet::parse(&data).unwrap();
                    let copy = Packet {
                        hdrs: packet.hdrs.clone(),
                        body: packet.body,
                    };

                    let cap = TestPacket {
                        port,
                        packet: Arc::new(copy),
                    };
                    tx.send(cap).unwrap();
                }
            }
        }
    }

    pub fn get_port_mac(&self, port: PhysPort) -> Result<MacAddr, String> {
        let idx: usize = port.into();
        if idx < self.ports.len() {
            if let Some(p) = &self.ports[idx] {
                return Ok(p.mac.expect(
                    format!(
                        "no MAC for {}/{} (phys port = {idx})",
                        p.port_id.to_string(),
                        *p.link_id,
                    )
                    .as_str(),
                ));
            }
        }
        Err("no such port".to_string())
    }

    pub fn collected_packets_clear(&self) {
        self.packets.lock().unwrap().clear()
    }

    pub fn collected_packets_get(&self) -> Vec<TestPacket> {
        self.packets.lock().unwrap().split_off(0)
    }

    pub fn packet_send(&self, port: PhysPort, packet: &Packet) {
        let data = packet.deparse().unwrap();

        let idx: usize = port.into();
        let p = self.ports[idx].as_ref().unwrap();
        p.pcap_out.send(&data).unwrap();
    }

    pub fn packet_test(
        &self,
        mut send: Vec<TestPacket>,
        mut expect: Vec<TestPacket>,
    ) -> TestResult {
        // NOTE: This timeout is critical.
        //
        // The tests are normally run against the Tofino simulator, a software
        // emulation of the ASIC. For reasons that aren't quite clear, it seems
        // to take some non-zero amount of time for things like adding routes to
        // "propagate" through the simulator.
        //
        // Specifically, if you set up a route and then immediately deliver a
        // packet to which that route applies, we _sometimes_ get ICMP-needed
        // packets on the CPU port. These are Sidecar-encapsulated IP packets,
        // which are delivered to the host system for completion. That's
        // required because packets like ICMP DUs are supposed to include the
        // first few bytes of the actual payload, data which is not immediately
        // available in the Sidecar P4 program -- so we ask the host software to
        // do that.
        //
        // This timeout here needs to be "long enough," so that those ICMP
        // packets are not generated. It's not clear exactly why they're ever
        // generated, since one would expect that the acknowledgement for
        // setting up a route would only arrive after the system has
        // fully-propagated it. That seems to be the case in hardware, or at
        // least it's fast enough to be practically the same.
        thread::sleep(self.packet_timeout);
        self.collected_packets_clear();
        for p in &send {
            self.packet_send(p.port, &p.packet);
        }

        let n_total_packets = send.len() + expect.len();
        let mut captured = Vec::with_capacity(n_total_packets);
        let now = std::time::Instant::now();
        while now.elapsed() < self.packet_timeout
            && captured.len() < n_total_packets
        {
            captured.extend(self.collected_packets_get());
            thread::sleep(Duration::from_millis(10));
        }

        let mut errors = Vec::new();
        if captured.len() != n_total_packets {
            errors.push(format!(
                "Captured unexpected number of packets: {} expected: {}",
                captured.len(),
                n_total_packets
            ));
        }

        // We should see all of the packets we put on the wire
        let mut found = Vec::new();
        for (s, sent) in send.iter().enumerate() {
            for (g, got) in captured.iter().enumerate() {
                if sent == got {
                    found.push(s);
                    captured.remove(g);
                    break;
                }
            }
        }
        while let Some(f) = found.pop() {
            send.remove(f);
        }

        // We should also see the packets we expected to see
        for (e, expected) in expect.iter().enumerate() {
            for (g, got) in captured.iter().enumerate() {
                if expected == got {
                    found.push(e);
                    captured.remove(g);
                    break;
                }
            }
        }
        while let Some(f) = found.pop() {
            expect.remove(f);
        }

        // Check that we've:
        //
        // 1. Captured all sent packets
        // 2. Captured all expected received packets
        // 3. We have no unexpected packets.
        //
        // The last item is part of the reason for the timeout at the entry to
        // this function. See the associated block comment for details.
        if !send.is_empty() {
            errors.push(format!("missing sent packets: {:?}", send.len()));
            println!("missing sent packets:");
            for p in send {
                p.show(self.verbosity);
            }
        }
        if !expect.is_empty() {
            errors
                .push(format!("missing expected packets: {:?}", expect.len()));
            println!("missing expected packets:");
            for p in expect {
                p.show(self.verbosity);
            }
        }
        if !captured.is_empty() {
            errors.push(format!("unexpected packets: {:?}", captured.len()));
            println!("unexpected packets:");
            for p in captured {
                p.show(self.verbosity);
            }
        }

        match errors.len() {
            0 => Ok(()),
            _ => Err(anyhow!(errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>()
                .join(", "))),
        }
    }
}

// Construct a single TCP packet with an optional payload
pub fn gen_tcp_packet_loaded(
    src: Endpoint,
    dst: Endpoint,
    body: &[u8],
) -> Packet {
    let tcp_stack = match src.get_ip("src").unwrap() {
        IpAddr::V4(_) => vec![ipv4::IPPROTO_TCP.into(), eth::ETHER_IPV4],
        IpAddr::V6(_) => vec![ipv6::IPPROTO_TCP.into(), eth::ETHER_IPV6],
    };

    Packet::gen(src, dst, tcp_stack, Some(body)).unwrap()
}

// Construct a single UDP packet with an optional payload
pub fn gen_udp_packet_loaded(
    src: Endpoint,
    dst: Endpoint,
    body: &[u8],
) -> Packet {
    let udp_stack = match src.get_ip("src").unwrap() {
        IpAddr::V4(_) => vec![ipv4::IPPROTO_UDP.into(), eth::ETHER_IPV4],
        IpAddr::V6(_) => vec![ipv6::IPPROTO_UDP.into(), eth::ETHER_IPV6],
    };

    Packet::gen(src, dst, udp_stack, Some(body)).unwrap()
}

// Construct a single ICMP packet with an optional payload
pub fn gen_icmp_packet_loaded(
    src: Endpoint,
    dst: Endpoint,
    body: &[u8],
) -> Packet {
    let icmp_stack = match src.get_ip("src").unwrap() {
        IpAddr::V4(_) => vec![ipv4::IPPROTO_ICMP.into(), eth::ETHER_IPV4],
        IpAddr::V6(_) => vec![ipv6::IPPROTO_ICMPV6.into(), eth::ETHER_IPV6],
    };

    Packet::gen(src, dst, icmp_stack, Some(body)).unwrap()
}

// Given an ingressing IP packet, generate a corresponding IP packet egressing
// the indicated port.
pub fn gen_packet_routed(
    switch: &Switch,
    phys_port: PhysPort,
    send: &Packet,
) -> Packet {
    let mut recv = send.clone();
    if recv.hdrs.ipv4_hdr.is_some() {
        ipv4::Ipv4Hdr::adjust_ttl(&mut recv, -1);
    } else if recv.hdrs.ipv6_hdr.is_some() {
        ipv6::Ipv6Hdr::adjust_hlim(&mut recv, -1);
    }

    let mac = switch.get_port_mac(phys_port).unwrap();
    eth::EthHdr::rewrite_smac(&mut recv, mac);
    recv
}

// Construct a pair of UDP packets with an optional payload.  The first
// represents the packet as it enters the switch.  The second represents the
// packet as it exits the switch via the specified port, heading to an upstream
// router with the provided mac address.
pub fn gen_udp_routed_pair_loaded(
    switch: &Switch,
    phys_port: PhysPort,
    router: MacAddr,
    src: Endpoint,
    dst: Endpoint,
    body: &[u8],
) -> (Packet, Packet) {
    let mut send = gen_udp_packet_loaded(src, dst, body);
    eth::EthHdr::rewrite_dmac(&mut send, router);

    let recv = gen_packet_routed(switch, phys_port, &send);
    (send, recv)
}

pub fn gen_udp_packet(src: Endpoint, dst: Endpoint) -> Packet {
    gen_udp_packet_loaded(src, dst, &Vec::new())
}

pub fn gen_tcp_packet(src: Endpoint, dst: Endpoint) -> Packet {
    gen_tcp_packet_loaded(src, dst, &Vec::new())
}

pub fn gen_icmp_packet(src: Endpoint, dst: Endpoint) -> Packet {
    gen_icmp_packet_loaded(src, dst, &Vec::new())
}

pub fn gen_udp_routed_pair(
    switch: &Switch,
    phys_port: PhysPort,
    router: MacAddr,
    src: Endpoint,
    dst: Endpoint,
) -> (Packet, Packet) {
    gen_udp_routed_pair_loaded(switch, phys_port, router, src, dst, &Vec::new())
}

// This utility routine creates a single cidr->subnet route.  If there is an
// existing route for this subnet, the call will fail.
async fn set_route_ipv6_common(
    switch: &Switch,
    subnet: &str,
    phys_port: PhysPort,
    gw: &str,
    vlan_id: Option<u16>,
) -> TestResult {
    let (port_id, link_id) = switch.link_id(phys_port).unwrap();
    let cidr = subnet.parse::<Ipv6Net>()?;
    let tgt_ip: Ipv6Addr = gw.parse()?;

    let route = types::RouteSet {
        cidr: IpNet::V6(cidr),
        target: types::RouteTarget::V6(types::Ipv6Route {
            port_id: port_id.clone(),
            link_id: link_id.clone(),
            tgt_ip,
            tag: switch.client.inner().tag.clone(),
            vlan_id,
        }),
        replace: false,
    };
    switch
        .client
        .route_ipv6_set(&route)
        .await
        .expect("Failed to add IPv6 route entry");

    let route = switch
        .client
        .route_ipv6_get(&cidr)
        .await
        .expect("Failed to get just-added IPv6 route entry")
        .into_inner();
    assert_eq!(
        route.len(),
        1,
        "Just added Ipv6-route has more than 1 entry"
    );
    assert_eq!(
        route[0].port_id, port_id,
        "Just-added IPv6 route entry doesn't match"
    );
    assert_eq!(
        route[0].link_id, link_id,
        "Just-added IPv6 route entry doesn't match"
    );
    assert_eq!(
        route[0].tgt_ip, tgt_ip,
        "Just-added IPv6 route entry doesn't match"
    );
    Ok(())
}

pub async fn set_route_ipv6(
    switch: &Switch,
    subnet: &str,
    phys_port: PhysPort,
    gw: &str,
) -> TestResult {
    set_route_ipv6_common(switch, subnet, phys_port, gw, None).await
}

pub async fn set_route_ipv6_vlan(
    switch: &Switch,
    subnet: &str,
    phys_port: PhysPort,
    gw: &str,
    vlan_id: u16,
) -> TestResult {
    set_route_ipv6_common(switch, subnet, phys_port, gw, Some(vlan_id)).await
}

pub async fn add_neighbor_ipv6(
    switch: &Switch,
    host: &str,
    mac: MacAddr,
) -> TestResult {
    let host: Ipv6Addr = host.parse()?;

    let entry = types::ArpEntry {
        ip: host.into(),
        mac: mac.into(),
        tag: switch.client.inner().tag.clone(),
        update: String::new(),
    };
    switch
        .client
        .ndp_create(&entry)
        .await
        .expect("Failed to add NDP entry");

    let neighbor = switch
        .client
        .ndp_get(&host)
        .await
        .expect("Failed to get just-added NDP entry")
        .into_inner();
    assert_eq!(
        neighbor.mac,
        mac.into(),
        "Just-added NDP entry doesn't match"
    );
    assert_eq!(neighbor.ip, host, "Just-added NDP entry doesn't match");
    Ok(())
}

async fn set_route_ipv4_common(
    switch: &Switch,
    subnet: &str,
    phys_port: PhysPort,
    gw: &str,
    vlan_id: Option<u16>,
) -> TestResult {
    let cidr = subnet.parse::<Ipv4Net>()?;
    let tgt_ip: Ipv4Addr = gw.parse()?;
    let (port_id, link_id) = switch.link_id(phys_port).unwrap();
    let route = types::RouteSet {
        cidr: IpNet::V4(cidr),
        target: types::RouteTarget::V4(types::Ipv4Route {
            port_id: port_id.clone(),
            link_id: link_id.clone(),
            tgt_ip,
            tag: switch.client.inner().tag.clone(),
            vlan_id,
        }),
        replace: false,
    };
    switch
        .client
        .route_ipv4_set(&route)
        .await
        .expect("Failed to add IPv4 route entry");

    let route = switch
        .client
        .route_ipv4_get(&cidr)
        .await
        .expect("failed to get just-added IPv4 route entry")
        .into_inner();
    assert_eq!(
        route.len(),
        1,
        "Just added IPv4-route has more than 1 entry"
    );
    assert_eq!(
        route[0].port_id, port_id,
        "Just-added IPv4 route entry doesn't match"
    );
    assert_eq!(
        route[0].link_id, link_id,
        "Just-added IPv4 route entry doesn't match"
    );
    assert_eq!(
        route[0].tgt_ip, tgt_ip,
        "Just-added IPv4 route entry doesn't match"
    );
    Ok(())
}

pub async fn set_route_ipv4(
    switch: &Switch,
    subnet: &str,
    phys_port: PhysPort,
    gw: &str,
) -> TestResult {
    set_route_ipv4_common(switch, subnet, phys_port, gw, None).await
}

pub async fn add_arp_ipv4(
    switch: &Switch,
    host: &str,
    mac: MacAddr,
) -> TestResult {
    let host: Ipv4Addr = host.parse()?;

    let entry = types::ArpEntry {
        ip: host.into(),
        mac: mac.into(),
        tag: switch.client.inner().tag.clone(),
        update: String::new(),
    };
    switch
        .client
        .arp_create(&entry)
        .await
        .expect("Failed to add ARP entry");

    let arp = switch
        .client
        .arp_get(&host)
        .await
        .expect("Failed to get just-added ARP entry")
        .into_inner();
    assert_eq!(arp.mac, mac.into(), "Just-added ARP entry doesn't match");
    assert_eq!(arp.ip, host, "Just-added ARP entry doesn't match");
    Ok(())
}

pub async fn add_ndp_ipv6(
    switch: &Switch,
    host: &str,
    mac: MacAddr,
) -> TestResult {
    let host: Ipv6Addr = host.parse()?;

    let entry = types::ArpEntry {
        ip: host.into(),
        mac: mac.into(),
        tag: switch.client.inner().tag.clone(),
        update: String::new(),
    };
    switch
        .client
        .ndp_create(&entry)
        .await
        .expect("Failed to add ARP entry");

    let ndp = switch
        .client
        .ndp_get(&host)
        .await
        .expect("Failed to get just-added NDP entry")
        .into_inner();
    assert_eq!(ndp.mac, mac.into(), "Just-added NDP entry doesn't match");
    assert_eq!(ndp.ip, host, "Just-added NDP entry doesn't match");
    Ok(())
}

pub fn add_sidecar_hdr(
    switch: &Switch,
    pkt: &mut packet::Packet,
    sc_code: u8,
    sc_ingress: PhysPort,
    sc_egress: PhysPort,
    payload: Option<&[u8]>,
) {
    let eth = pkt.hdrs.eth_hdr.as_mut().unwrap();
    let sc_ether_type = eth.eth_type;
    let sc_payload = [0u8; 16];

    let mut s = sidecar::SidecarHdr {
        sc_code,
        sc_pad: 0,
        sc_ingress: switch.tofino_port(sc_ingress),
        sc_egress: switch.tofino_port(sc_egress),
        sc_ether_type,
        sc_payload,
    };

    if let Some(p) = payload {
        s.sc_payload.copy_from_slice(&p[0..16]);
    }

    pkt.hdrs.sidecar_hdr = Some(s);
    eth.eth_type = eth::ETHER_SIDECAR;
}

pub fn set_icmp_needed(
    switch: &Switch,
    pkt: &mut packet::Packet,
    ingress: PhysPort,
    egress: PhysPort,
    icmp_code: u8,
    icmp_type: u8,
) {
    let payload: u128 = ((icmp_code as u128) << 8) | (icmp_type as u128);

    add_sidecar_hdr(
        switch,
        pkt,
        sidecar::SC_ICMP_NEEDED,
        ingress,
        egress,
        Some(&payload.to_be_bytes()),
    )
}

pub fn set_icmp_unreachable(
    switch: &Switch,
    pkt: &mut packet::Packet,
    ingress: PhysPort,
) {
    set_icmp_needed(
        switch,
        pkt,
        ingress,
        NO_PORT,
        packet::icmp::ICMP_DEST_UNREACH,
        packet::icmp::ICMP_NET_UNREACH,
    );
}

pub fn set_icmp6_unreachable(
    switch: &Switch,
    pkt: &mut packet::Packet,
    ingress: PhysPort,
) {
    set_icmp_needed(
        switch,
        pkt,
        ingress,
        NO_PORT,
        icmp::ICMP6_DST_UNREACH,
        icmp::ICMP6_DST_UNREACH_NOROUTE,
    );
}

pub fn gen_ipv4_ping(
    icmp_type: u8,
    icmp_code: u8,
    src: Endpoint,
    tgt: Endpoint,
) -> Packet {
    let type_code: u16 = (icmp_type as u16) << 8 | icmp_code as u16;

    Packet::gen(
        src,
        tgt,
        vec![type_code, ipv4::IPPROTO_ICMP as u16, eth::ETHER_IPV4],
        None,
    )
    .unwrap()
}

pub fn gen_arp_reply(src: Endpoint, tgt: Endpoint) -> Packet {
    Packet::gen(src, tgt, vec![arp::ARPOP_REPLY, eth::ETHER_ARP], None).unwrap()
}

pub mod prelude {
    pub use super::get_switch;
    pub use super::PhysPort;
    pub use super::Switch;
    pub use super::TestPacket;
    pub use super::TestResult;
    pub use super::NO_PORT;
    pub use super::SERVICE_PORT;
}
