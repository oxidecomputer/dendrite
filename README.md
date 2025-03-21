# dendrite

This contains the components needed to drive and manage the Oxide rack switch:

* `sidecar` - the p4 program that runs on the Tofino ASIC in the switch
* `dpd` - the user-space daemon that manages the dataplane tables provided by the p4 program.  This daemon is controlled via an OpenAPI interface.
* `tfportd` - the user-space daemon that manages the `tfport` devices, which correspond to ports on the switch, and which syncronizes port-related network state (e.g., `ndp` and `arp` tables) with `dpd`.  This daemon is only supported on `illumos` and will fail to build on `linux`.
* `swadm` - a command-line utility that is used to update the p4 tables manually and to report the contents of the tables and other switch state.  This tool is essentially a wrapper around the OpenAPI interface to `dpd`.

## Environment variables

The SDE software as well as scripts in this repo use a number of environment
variables for configuration, including finding tools, the Sidecar p4 program,
and more. This list is non-exhaustive, but should provide a starting point.

- `$SDE`: The root of the installed BF SDE. This is assumed by both SDE scripts
  and some Dendrite scripts, and should generally be a full, canonical path, as
  tools in both repos look for things in a relative and absolute fashion.

### p4

The first step is building the p4 program that runs on the Tofino ASIC. This is
`dpd/p4/sidecar.p4`, and currently must be compiled using the Barefoot p4
compiler that only runs on Linux.

To build the p4 program:

```
$ cargo xtask codegen [ -n <p4 program name> ] [--sde <sde directory> ]
```

By default `codegen` will use the SDE installed at `/opt/oxide/bf`, which is the default location on Linux, to build the `sidecar` program, which is intended to run on the Oxide rack switch.
Note that on Helios the default installation can be found at `/opt/oxide/bf_sde`.
Note that the provided SDE directory is not canonicalized, so should be
specified as a full path, e.g., `$HOME/bf_sde`.

To run the compiled p4 program on the Tofino model on a Linux system:

* Enable hugepages for DMA support by adding the following line to `/etc/sysctl.conf`, and reboot:
```
vm.nr_hugepages = 128
```
* start the model:

```
    $ sudo ./tools/veth_setup.sh
    $ [ SDE=/path/to/bf_sde ] ./tools/run_tofino_model.sh [ -p <p4 program> ]
```

If you don't set or override the `SDE` environment variable, it will default to
using the SDE installed in `/opt/oxide/bf`. This is the default install
location on Linux whereas on Helios, set `SDE=/opt/oxide/bf_sde` for the
default installation.

If you don't specify which p4 program to use, it will use the `sidecar` program.
The model doesn't actually run the p4 code being pointed at here.  It will run
the code that the daemon pushes to it - just as the real ASIC would.  The model
just uses the provided p4 artifact to provide more meaningful information in the
debug log.

The `veth_setup.sh` script only needs to be run once per boot, as the devices it creates
will persist across multiple launches of the model.

If you are running a model installed from a package:

    $ /opt/oxide/dendrite/bin/run_tofino_model.sh [ -p <p4 program> ]

### Userspace

> NOTE: Building `dendrite` requires a minimum supported Rust version of 1.62.

To build `dendrite`'s user-space code in linux for use with the Tofino simulator:

```
	$ pfexec pkg install clang-15		(illumos only)
	$ cargo build
```

To build `dendrite`'s user-space code for use without the simulator:

```
	$ pfexec pkg install clang-15		(illumos only)
	$ cargo build --features tofino_stub
```

To start the controller daemon when running out of a workspace:

```
    $ ./tools/run_dpd.sh [ -p <p4 program name> ] [ -m <model host> -x none ]
```

By default, `run_dpd.sh` will run the daemon that interacts with the `sidecar`
p4 program.  If you are running a different p4 program, you will need to provide
a daemon that understands its tables.

By default, `dpd` will attempt to find a real tofino ASIC to interact with.  If
you want to run `dpd` with the tofino simulator, you need to provide the `-m`
flag with the IP address of the model.  For a model running on the same system
as `dpd`, this would be `-m 127.0.0.1`.  When running with a model, you should
also specify "-x none" to minimize error messages arising from the daemon
looking for transcievers that will never be found.

Note that `run_dpd.sh` requires the build artifacts from `cargo xtask codegen`,
but that code-generation (p4 compilation) is not supported on illumos. That
means you'll need to run that step on Linux, where you run the model, and then
copy over the `target/proto` directory that step generates. Place it in the same
location.  If you aren't modifying the `p4` code, then you can install the
appropriate CI-generated artifacts by running:
```
$ cargo xtask p4fetch
    Finished dev [unoptimized + debuginfo] target(s) in 0.22s
     Running `target/debug/xtask p4fetch`
Downloading p4 artifacts from https://buildomat.eng.oxide.computer/public/file/oxidecomputer/dendrite/linux/004e0fd01be4c40506be2ff7df12d4fd2e7c442c/p4_artifacts.tgz
$ cargo xtask p4untar
    Finished dev [unoptimized + debuginfo] target(s) in 0.22s
     Running `target/debug/xtask p4untar`
$ ls target/proto/opt/oxide/bf_sde/share/tofino2pd/sidecar/pipe/tofino2.bin
-rw-r--r--   1 nils     staff    1769867 Mar  9 23:04 target/proto/opt/oxide/bf_sde/share/tofino2pd/sidecar/pipe/tofino2.bin
```

> IMPORTANT: `run_dpd.sh` may complain or fail to start with a few opaque error
> modes. One is `no p4 config file found at...`, and another is `dpd` apparently
> just hanging doing nothing after printing a log message starting with
> `"initialized QSFP management"`. Both of these indicate that they P4 artifacts
> needed to actually run the thing are not downloaded or installed.
>
> Make sure you do the following:
>
> ```
$ cargo xtask pf4fetch
$ (mkdir -p target/proto ; cd target/proto ; tar xf ../../p4_artifacts_$COMMIT.tgz)
> ```
> where `$COMMIT` is whatever was spat out by `cargo xtask p4fetch`.

To start the tfportd daemon and have it process packets from the `vioif1`
device:

```
    $ pfexec env PKTSRC=vioif1 ./target/debug/tfportd
```

When running the daemons from an installed package, they can be launched with:

```
    $ /opt/oxide/dendrite/bin/run_dpd.sh
    $ sudo env PKTSRC=vioif1 /opt/oxide/dendrite/bin/tfportd
```

### In action

To build a network with the switch moving traffic between rack hosts and the
outside world, we will use 4 VMs running on top of an illumos host.

* The switch will be run in a Linux VM hosted by illumos.  This VM runs a
  Tofino2 ASIC emulator and both `dendrite` user-space daemons.  We will call
  that VM *sidecar*.

* The two rack hosts can be VMs running any OS, although Helios would best
  represent the real Oxide configuration.  We call them *gimlet0* and *gimlet1*.

* Finally, there is a VM representing an upstream switch - that is, the first
  endpoint we connect to running outside of the rack.  This VM can be any OS
  capable of acting as an IPv6 router.  The configuration of that switch VM is
  outside of the scope of this README.

* In the illumos host, we create a vnic for each client, which will get plumbed
  into the client VM.  Each vnic will have a corresponding vnic which will get
  plumbed into the switch VM.  The two vnics are layered on top of simnet
  devices, which are connected together.  This essentially implements an
  ethernet cable connecting the client's ethernet NIC to a port in the switch.

```
	for port in {0..1} ; do
        	for side in c s; do
                	sim=${side}sim${port}
                	vnic=${side}nic${port}
                	pfexec dladm create-simnet -t ${sim}
                	pfexec dladm create-vnic -t -l ${sim} ${vnic}
        	done
        	pfexec dladm modify-simnet -t -p csim${port} ssim${port}
	done
```

* In the *sidecar* VM, we use bridges to route packets arriving on the vnic
  device to the veth devices used by the switch:

```
	# create a bridge for each port:
	$ brctl addbr port0
	$ brctl addbr port1
	$ brctl addbr port24

	# enable them:
	$ ifconfig port0 up
	$ ifconfig port1 up
	$ ifconfig port24 up

	# for each port, connect both the asic and the vnic to the port's bridge:
	$ brctl addif port0 veth1
	$ brctl addif port0 enp0s6f1

	$ brctl addif port1 veth3
	$ brctl addif port1 enp0s6f2

	$ brctl addif port24 veth33
	$ brctl addif port24 enp0s6f3

	# enable the vnics:
	$ ifconfig enp0s6f1 up
	$ ifconfig enp0s6f2 up
	$ ifconfig enp0s6f3 up
```

 * The following shows how to assign mac addresses and ipv4 addresses to the
  three configured ports.  We also assign ipv6 addresses to the "host" ports.
  SLAAC (`ndp` running in the service daemon) will assign the ipv6 address to the "uplink" port.

```
	export ADM=./target/debug/swadm

	export HOST="8 9"
	export UPLINK=24
	export PORTS="$HOST $UPLINK"

	for port in $PORTS; do
		$ADM port set -p $port -a mac -v 00:40:54:$port:$port:$port
	done

	for port in $HOST; do
		$ADM port set -p $port -a ipv4 -v 10.10.$port.1
		$ADM port set -p $port -a prefix -v fc00:aabb:ccdd:01$port::0/64
	done

	for port in $UPLINK; do
		$ADM port set -p $port -a ipv4 -v 10.10.$port.2
	done

	# assign subnet routes for the two gimlets
	$ADM route add 10.10.8.0/24 8 10.10.8.2
	$ADM route add 10.10.9.0/24 9 10.10.9.2

	# set a default route for port 24.
	$ADM route add 0.0.0.0/0 24 10.10.24.1
```

The end result will be a network that looks like the following (with only a single *gimlet* instance shown):

```
+==========================================================================================+
|     +------------------------------------------------------------------------------+     |
|     |        ........................          ............................        |     |
|     |        .         dpd          .          .           tfportd        .        |     |
|     |        .(dataplane controller).          . (manages tfport devices) .        |     |
|     |        ........................          ............................        |     |
|     |                  ↑                                     ↑                     |     |
|     |                  |                                  vioif1                   |     |
|     |       +----------+---------------------------------+   |                     |     |
|     |       |         tofino ASIC emulator               |   |                     |     |
|     |       |                                   PCI Port +---+                     |     |
|     |       |    port 8          port 24                 |                         |     |
|     |       | (10.10.8.1)     (10.10.24.1)               |                         |     |
|     |       +------+----------------+--------------------+                         |     |
|     |              |                |                                              |     |
|     |   +----------+                +--------+                     "sidecar"       |     |
|     |   |                                    |                     (linux VM)      |     |
|     | veth0                                veth32                                  |     |
|     +---+-------------------------------------+--------------------------+---------+     |
|         |                                     |                          |               |
|       snic0                                 snic1                        |               |
|         |                                     |                       sidecar0           |
|      simnet0                               simnet1                       |               |
|         |                                     |                          |               |
|       cnic0                                 cnic1                        +---------+     |
|         |                                     |                                    |     |
|    +---------------------+             +-------------------------+               ixgbe0--+-->
|    |  enp0s6 (10.10.8.2) |             | enp0s6f1 (10.10.24.2)   |                 |     |
|    |                     |             |                         |                 |     |
|    |     "gimlet0"       |             | "switch"       enp0s6f0 |                 |     |
|    |                     |             |           (192.168.5.58)+-------bsd0------+     |
|    |     (linux VM)      |             |                         |                       |
|    |                     |             |       (FreeBSD VM)      |                       |
|    +---------------------+             +-------------------------+    "sebago"           |
|                                                                      illumos on AMD      |
|                                                                                          |
+==========================================================================================+
```

#### Using `dpd` and `swadm` with `softnpu`
ASIC emulation can be achieve by using `softnpu` as a standalone binary
or integrated into `propolis`. If you are using a `softnpu` asic, you
will need to compile `dpd` with the correct feature and optionally specify
management communication options when starting `dpd`.

* Install `scadm`

`scadm` is a cli tool for directly interacting with the Softnpu ASIC running the
sidecar-lite p4 program. This tool is helpful for verifying that `dpd` is actually
making the expected changes to the Softnpu ASIC.

You can build this from [source](https://github.com/oxidecomputer/sidecar-lite) or you can
[download](https://buildomat.eng.oxide.computer/wg/0/artefact/01GR77X1ZN2K42ADY9F295G92R/RSLufKkz5jxTSULkWrCvQtt3ill3ss9OMAD1PM22thnCxn07/01GR77XAMRNB1CV8F615Z4AS5R/01GR789KFDZ35V73AJRYD0XF3R/scadm) the prebuilt artifact from Buildomat

* Build `dpd` and `swadm`

``` sh
$ cargo build --features softnpu --bin dpd --bin swadm --release`
```

* Start Softnpu

(this is just an example command, please see
[softnpu](https://github.com/oxidecomputer/softnpu) for more details.)

``` sh
$ pfexec ./softnpu softnpu.toml
```

* Start `dpd`

``` sh
$ pfexec ./target/release/dpd run --softnpu-management uds --port-config sidecar-ports.toml
```

`--softnpu-management` is an optional flag that specifies whether to use
UART or a UNIX domain socket (uds) to communicate with `softnpu`. This
flag defaults to `uart`

`--uds-path` is an optional flag for specifying the directory where the
`softnpu` socket files are located. This defaults to `/opt/softnpu/stuff`. This
flag is ignored unless `--softnpu-management uds` is specified.

* Use `swadm` to configure `softnpu` via `dpd`
Currently we are able to configure port mac addresses and nat via `softnpu`.
More features will be added in the future as needed.

Configuring a nat entry using `swadm`:
``` sh
$ ./target/release/swadm nat add \
    -e 10.85.0.211 \
    -h 65535 \
    -m A8:40:25:F6:F9:94 \
    -i fd00:1122:3344:101::1 \
    -l 1024 \
    -v 13546814
```

Verifying state of `softnpu` asic via `scadm`:
``` sh
$ pfexec scadm standalone dump-state
local v6:
local v4:
router v6:
router v4:
resolver v4:
resolver v6:
nat_v4:
10.85.0.211 1024/65535 -> fd00:1122:3344:101::1 13546814/a8:40:25:f6:f9:94 <-- new entry
nat_v6:
port_mac:
0: a8:40:25:e5:0a:2b
1: a8:40:25:e5:0a:2c
icmp_v6:
icmp_v4:
proxy_arp:
```

### Testing
* SDE needs to be installed if you want to test with the `tofino_asic` feature.
* Openapi tests / regeneration can only be executed with the `tofino_asic` feature.

1. Download the latest bf_sde.p5p artifact from the bf_sde repo
2. run `pkg install -g /path/to/bf_sde.p5p bf_sde` to install the package
3. run `SDE=/opt/oxide/bf_sde cargo test --features=<feature>` to execute
   the tests.

If regenerating the openapi specifications, set `EXPECTORATE=overwrite` when
runnning the tests with the `tofino_asic` feature.
