// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::IpAddr;
use std::sync::Mutex;

use slog::debug;

use crate::{now, Global};
use packet::Packet;

// An enqueued packet awaiting resolution of an IP to MAC address.
struct QueuedPacket {
    // The time after which we drop the packet.
    expires_at: i64,
    // The IP address for which this packet is awaiting resolution.
    queued_on: IpAddr,
    // The headers for the packet.
    hdrs: packet::Headers,
    // The raw body of the packet.
    body: Option<Vec<u8>>,
    // An arbitrary index.
    idx: u64,
}

impl QueuedPacket {
    fn new(p: Packet, queued_on: IpAddr, ms: i64, idx: u64) -> Self {
        QueuedPacket {
            expires_at: now() + ms,
            queued_on,
            hdrs: p.hdrs,
            body: p.body,
            idx,
        }
    }
}

/// A queue of packets awaiting resolution of an IP to MAC address.
pub struct PacketQueue {
    name: String,
    max: usize,
    cnt: u64,
    queue: Vec<QueuedPacket>,
}

impl PacketQueue {
    /// Create a new, empty packet queue
    pub fn new(name: impl ToString, max: usize) -> Self {
        PacketQueue {
            name: name.to_string(),
            max,
            cnt: 0,
            queue: Vec::new(),
        }
    }

    /// Pull all of the packets from the queue that were waiting on the given IP
    /// address.
    pub fn pull(&mut self, g: &Global, queued_on: IpAddr) -> Vec<Packet> {
        let p: Vec<usize> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, pkt)| pkt.queued_on == queued_on)
            .map(|(idx, _)| idx)
            .collect();

        let mut pkts = Vec::new();
        for idx in p.iter().rev() {
            let qp = self.queue.remove(*idx);
            if qp.expires_at < now() {
                debug!(g.log, "dropping expired packet";
                "iface" => &self.name,
                "idx" => qp.idx);
            } else {
                debug!(g.log, "pulled packet for retransmit";
                "iface" => &self.name,
                "idx" => qp.idx);

                pkts.push(Packet {
                    hdrs: qp.hdrs,
                    body: qp.body,
                });
            }
        }
        pkts
    }

    /// Push the provided packet onto the port's pending queue, and remember the IP
    /// address on which it depends.
    pub fn push(&mut self, g: &Global, pending: IpAddr, p: Packet) {
        while self.queue.len() >= self.max {
            let x = self.queue.remove(0);
            debug!(
                g.log,
                "port {}: dropping overflow pkt {}", self.name, x.idx
            );
        }

        self.cnt += 1;
        let q = QueuedPacket::new(p, pending, 5000, self.cnt);
        debug!(
            g.log,
            "port {}: pushed {} pending {}", self.name, q.idx, pending
        );
        self.queue.push(q);
    }
}

/// Given a tofino ASIC ID, ensure that a packet_queue exists to hold packets
/// pending ARP/NDP resolution
pub fn ensure_queue_exists(g: &Global, name: &str, asic_id: u16) {
    let mut queues = g.queues.lock().unwrap();
    if queues.get(&asic_id).is_none() {
        debug!(g.log, "Created packet queue for asic_id {asic_id}");
        queues.insert(asic_id, Mutex::new(PacketQueue::new(name, 8)));
    }
}

/// Given a tofino ASIC ID, ensure that any associated packet_queue is removed
pub fn ensure_queue_removed(g: &Global, asic_id: u16) {
    let mut queues = g.queues.lock().unwrap();
    if queues.remove(&asic_id).is_some() {
        debug!(g.log, "Removed packet queue for asic_id {asic_id}");
    }
}
