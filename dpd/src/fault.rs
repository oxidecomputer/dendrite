// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::link::LinkFsmCounter;
use asic::FsmStats;
use asic::PortFsmState;

// The following constants define the limits of normal/acceptable behavior.
// They seem like reasonable first guesses, but we should expect to tune them
// as we get more experience with the system.  Rather than hardcoding these as
// constants we could make them tunable via environment variables or swadm
// operations.

// If we see a link toggle from down to up more than 5 times in 60 seconds,
// we assume it is a "link flapping" state.
const LINK_UP_LIMIT: usize = 5;
const LINK_UP_WINDOW: Duration = Duration::from_secs(60);

// If we see a link's autonegotiation finite state machine restart more than 5
// times in 60 seconds, we assume we are running into some physical/external
// issue that requires operator attention.
const AUTONEG_RESTART_LIMIT: usize = 5;
const AUTONEG_RESTART_WINDOW: Duration = Duration::from_secs(60);

/// A Limiter is used to detect when an event's frequency exceeds some limit.
/// The limit is defined by specifying the number of times that an event may
/// occur within a specific timespan.
struct Limiter {
    event_name: String,               // the event being tracked
    event_limit: usize,               // maximum number of events allowed
    window: Duration, // timespan over which the count is limited
    timestamps: Vec<Option<Instant>>, // ring buffer of event timestamps
    cursor: usize,    // index into the ring buffer
}

impl Limiter {
    /// Create a new Limiter with the given limits
    pub fn new(
        event_name: impl ToString,
        event_limit: usize,
        window: Duration,
    ) -> Self {
        Limiter {
            event_name: event_name.to_string(),
            event_limit,
            window,
            timestamps: vec![None; event_limit],
            cursor: 0,
        }
    }

    /// Clear the ring buffer
    pub fn reset(&mut self) {
        self.timestamps = vec![None; self.event_limit];
        self.cursor = 0;
    }

    /// Record an event timestamp.  Returns an error if this event exceeds the
    /// number of allowed events within the defined window.
    pub fn record_event(&mut self) -> Result<(), String> {
        let oldest = self.timestamps[self.cursor];
        self.timestamps[self.cursor] = Some(Instant::now());
        self.cursor = (self.cursor + 1) % self.event_limit;

        match oldest {
            Some(oldest) => match oldest.elapsed() {
                elapsed if elapsed < self.window => Err(format!(
                    "{} {} in {} seconds",
                    self.event_limit,
                    self.event_name,
                    elapsed.as_secs()
                )),
                _ => Ok(()),
            },
            None => Ok(()),
        }
    }
}

/// A Fault represents a specific kind of failure, and carries some additional
/// context.  Currently Faults are only used to describe Link failures, but
/// there is no reason they couldn't be used elsewhere.
#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum Fault {
    LinkFlap(String),
    Autoneg(String),
    Injected(String),
}

/// The Faultable trait is implemented by metadata structures whose values could
/// indicate that the link/device/construct has entered a failed state that
/// requires admin intervention to correct.
///
/// The conceptual model is that the metadata is updated by external events, and
/// some set of events will conspire to push the link into a Fault state.  We
/// track both "current" events and "total" events.  Current events are those
/// that have occurred since the link was last enabled.  Total events are all of
/// those that have occurred since the link was originally created.
///
/// Obviously this model and interface is entirely driven by the needs of the
/// first two consumers, and may need to be extended or rethought before it is
/// more generally useful.  It may even be the case that the sources of faults
/// are too varied to make a common trait worthwhile.
pub trait Faultable<E> {
    /// An event has occurred which will update the Faultable structure
    fn process_event(&self, event: &E) -> Option<Fault>;
    /// Reset the counters for the current incarnation of the tracked entity.
    fn reset(&self);
    #[allow(dead_code)]
    /// Reset the counters for the current and historical incarnations of the tracked entity.
    fn reset_all(&self);
}

/// A LinkUpTracker is used to count how many times a link has transitioned from
/// Down to Up, and thus implicitly from Up to Down.
#[derive(Debug)]
pub struct LinkUpTracker {
    inner: Mutex<LinkUpTrackerInner>,
}

pub struct LinkUpTrackerInner {
    current: u32,
    total: u32,
    limiter: Limiter,
}

// We implement Debug manually to keep the Limiter info from clogging up
// the Debug output for struct Link.
impl fmt::Debug for LinkUpTrackerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LinkUpTracker(current: {} total: {})",
            self.current, self.total
        )
    }
}

impl Faultable<()> for LinkUpTracker {
    fn process_event(&self, _event: &()) -> Option<Fault> {
        let mut inner = self.inner.lock().unwrap();
        inner.current += 1;
        inner.total += 1;
        match inner.limiter.record_event() {
            Err(e) => Some(Fault::LinkFlap(e)),
            Ok(()) => None,
        }
    }

    fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.current = 0;
        inner.limiter.reset();
    }

    fn reset_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.current = 0;
        inner.total = 0;
        inner.limiter.reset();
    }
}

impl Default for LinkUpTracker {
    fn default() -> Self {
        LinkUpTracker {
            inner: Mutex::new(LinkUpTrackerInner {
                limiter: Limiter::new(
                    "link up events",
                    LINK_UP_LIMIT,
                    LINK_UP_WINDOW,
                ),

                current: 0,
                total: 0,
            }),
        }
    }
}

impl LinkUpTracker {
    pub fn get_counters(&self) -> (u32, u32) {
        let inner = self.inner.lock().unwrap();
        (inner.current, inner.total)
    }
}

/// An AutonegTracker is used to count how many times a link has entered each
/// state in the autonegotiation/link-training finite state machine.  We don't
/// assume anything about the ordering and/or number of states in the machine.
/// As currently implemented, the tracker only knows about those states that a
/// link has entered - not all of the possible states.  Thus, we will never see
/// a state with a count of 0.
#[derive(Debug)]
pub struct AutonegTracker {
    inner: Mutex<AutonegTrackerInner>,
}

pub struct AutonegTrackerInner {
    current: FsmStats,
    total: FsmStats,
    limiter: Limiter,
}

// We implement Debug manually to keep the Limiter info from clogging up
// the Debug output for struct Link.
impl fmt::Debug for AutonegTrackerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AutonegTracker(current: {:?} total: {:?})",
            self.current, self.total
        )
    }
}

impl Faultable<PortFsmState> for AutonegTracker {
    fn process_event(&self, event: &PortFsmState) -> Option<Fault> {
        let mut inner = self.inner.lock().unwrap();
        inner.current.bump(*event);
        inner.total.bump(*event);
        match *event {
            PortFsmState::Idle => match inner.limiter.record_event() {
                Err(e) => Some(Fault::Autoneg(e)),
                Ok(()) => None,
            },
            _ => None,
        }
    }

    fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.current = FsmStats::new();
        inner.limiter.reset();
    }

    fn reset_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.current = FsmStats::new();
        inner.total = FsmStats::new();
        inner.limiter.reset();
    }
}

impl Default for AutonegTracker {
    fn default() -> Self {
        AutonegTracker {
            inner: Mutex::new(AutonegTrackerInner {
                limiter: Limiter::new(
                    "finite state machine restarts",
                    AUTONEG_RESTART_LIMIT,
                    AUTONEG_RESTART_WINDOW,
                ),
                current: FsmStats::new(),
                total: FsmStats::new(),
            }),
        }
    }
}

impl AutonegTracker {
    /// Get a processed list of the FsmCounter data suitable for exporting
    /// as JSON data.
    pub fn get_counters(&self) -> Vec<LinkFsmCounter> {
        let inner = self.inner.lock().unwrap();
        inner
            .total
            .states()
            .iter()
            .map(|state| LinkFsmCounter {
                state_name: state.to_string(),
                current: inner.current.get(*state),
                total: inner.total.get(*state),
            })
            .collect()
    }

    /// Get a copy of the raw counter data, suitable for processing into
    /// oximeter data.
    pub fn get_raw_counters(&self) -> FsmStats {
        self.inner.lock().unwrap().total.clone()
    }
}
