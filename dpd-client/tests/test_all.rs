// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

// We use a `std::sync::Mutex` to lock the shared integration test state.
// Technically, we could use an async-aware mutex here to increase parallelism.
// But we're explicitly looking for a single thread to run at a time, so we
// actually don't care that you can't move the task between threads.
#![allow(clippy::await_holding_lock)]

#[cfg(target_os = "linux")]
mod integration_tests;

#[cfg(feature = "chaos")]
mod chaos_tests;
