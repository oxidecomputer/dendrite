# Dendrite integration tests

The Dendrite integration tests verify the `dpd` API server as well as the
behavior of the P4 program that runs on the real Sidecar switch. The tests are
run with the usual `cargo test` invocation, though they may be controlled with a
variety of environment variables, described below.

## tl;dr

From an ubutnu 20.04 or 22.04 LTS machine run the following CI job locally.

```
.github/buildomat/jobs/packet-test.sh
```

## Setup

Dendrite integration tests are currently run against the real `dpd` and the
Tofino simulator. `dpd` may run anywhere, and should be compiled with
`--features tofino_asic`. When it is invoked, one should specify the host
running the simulator, with the `./tools/run_dpd.sh -m <MODEL_HOST>` argument.

The simulator must be run on Linux. First, follow the directions in the
`bf_sde` repository for building the SDE on Linux. Then one needs to create the
`veth` links used to simulate the switch-ports, using `tools/veth_setup.sh`.
These can be destroyed with `tools/veth_teardown.sh`. Finally, run the Tofino
simulator with `./tools/run_tofino_model.sh`.

```bash
$ ./tools/run_tofino_model.sh
```

These integration tests must also currently be run on Linux. This is due to the
fact that we run the simulator on top of several `veth` devices, and then verify
the behavior of the Sidecar P4 program by capturing packets on those. While we
can capture packets on illumos systems, those captures need to run on the same
system as the `veth` devices that the simulator works over.

Because of this, the tests are compiled out on non-Linux machines.

> NOTE: The tests require elevated permissions, since they rely on capturing
 packets to verify behavior. This should be handled automatically, by setting
 the [target runner](https://doc.rust-lang.org/cargo/reference/config.html#targettriplerunner)
 to run tests via `sudo -E`. Note that this will _not_ work if we add new
 binaries to the `dpd-client` crate.

> **IMPORTANT**: Because of all of these caveats and setup required of the
 surrounding test environment, the integration tests are currently marked as
 `#[ignore]`. You must run the tests with `cargo test -- --ignored`. This makes
 sure that we know the tests _exist_ when just running `cargo test` at the
 workspace, and we're choosing only to run them when requested.

## Test families

Each module of the tests is designed to exercise a particular family of
behavior, such as NAT or IPv6 routing. If you're only interested in one such
family, use `cargo test -- --list` to see which modules are available.

## Environment variables

All environment variables are prefixed by `DENDRITE_TEST_` for clarity.

- `DENDRITE_TEST_HOST`: The IP address or hostname of the machine running `dpd`.
  Default is `localhost`.
- `DENDRITE_TEST_PORT`: The port of the `dpd` API server. Default is `12224`,
  which is `dpd`'s default as well.
- `DENDRITE_TEST_API_ONLY`: If true, only the Dendrite API is tested, but no
  tests requiring networking itself are actually run.
- `DENDRITE_TEST_VERBOSITY`: The verbosity of the test output on failures. This
  is a bit mask. The first bit controls whether to print the display or debug
  representation of packets on failure. The second bit controls whether to
  display the hex of each packet body as well.
- `DENDRITE_TEST_TIMEOUT`: The amount of time to wait for any single test's
  network traffic to complete, specified in milliseconds.  The default is 500,
  which works for a reasonably powerful system under light load.

## Parallelization

The tests cannot currently be parallelized, since they rely on predictable state
shared with a single instance of `dpd`. This is enforced with a shared lock, so
running the tests with `--test-threads` has no real effect. This may change in
the future by running each test against a different `dpd` and Tofino simulator
(or SoftNPU backend), though that is currently unplanned.
