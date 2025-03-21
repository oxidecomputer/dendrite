# Running on real hardware

Typically we expect `dendrite` to be run as a service inside an `omicron` switch
zone.  However, it is often useful to be able to run `dendrite` as a standalone
project, without all the depenencies and complexities of `omicron`.

### Running `dpd` in the global zone

1. Download a "global zone" build from the `image` CI job.
2. Copy that to the scrimlet
3. Unpack:
```
06:57:47 BRM42220057:/$ tar xf /root/dendrite-global.tar.gz
```
4. Run:
```
06:58:01 BRM42220057:/$ /opt/oxide/dendrite/bin/run_dpd.sh -p /opt/oxide/dendrite/misc/sidecar_config.toml
Looking for p4 in package install directory: /opt/oxide/bf_sde
Using SDE runtime support at: /opt/oxide/bf_sde
Using config file: /opt/oxide/bf_sde/share/p4/targets/tofino2/sidecar.conf
[...]
ioctl() returned 272
ILLUMOS: skipping sysfs write to cold reset the kpkt device
trigger tfpkt reset
BF_DMA_PIPE_LEARN_NOTIFY_dev_0_0_Pool has 1572864, wastes 524288 bytes
BF_DMA_MAC_STAT_RECEIVE_dev_0_0_Pool has 266240, wastes 1830912 bytes
[...  it will pause here for a while.  After a sidecar powercycle, this could be 1-2 minutes ...]
port_admin_int_cb(0, 444) -> true
port_status_int_cb(0, 2) -> true
bf_pltfm_port_led_set
port_status_int_cb(0, 8) -> true
bf_pltfm_port_led_set
port_status_int_cb(0, 448) -> true
{"msg":"front IO controller not initialized, reporting all modules as absent","v":0,"name":"dpd","level":20,"time":"1987-01-09T18:59:57.71161765Z","hostname":"BRM42220057","pid":23209,"unit":"qsfp-ffi"}
[...]
```
5. In another window, you can verify that things are running:
```
07:01:10 BRM42220057:/data/nils$ /opt/oxide/dendrite/bin/swadm port list
 NAME  MEDIA    SPEED   FEC     ENA   LINK  MAC              
  1:0  Copper   100G    None    Ena   Down  a8:40:25:65:83:43
  2:0  Copper   100G    None    Ena   Down  a8:40:25:65:83:44
[...]
 31:0  Copper   100G    None    Ena   Down  a8:40:25:65:83:61
 32:0  Copper   100G    None    Ena   Down  a8:40:25:65:83:62
  CPU  CPU      10G     None    Ena   Down  a8:40:25:65:83:42
```

### Running `tfportd` in the global zone

Once the `dpd` daemon is running, you can also launch the `tfportd` daemon:

```
07:09:26 BRM42220057:~$ /opt/oxide/dendrite/bin/tfportd --pkt-source tfpkt0
Jan 09 19:09:29.995 DEBG client request, body: None, uri: http://localhost:12224/dpd-version, method: GET, unit: tfportd-client
[...]
```

To verify that it is running successfully, use `ipadm` to look for link-local
addresses on `tfport` interfaces:

```
07:01:33 BRM42220057:/data/nils$ ipadm
ADDROBJ           TYPE     STATE        ADDR
lo0/v4            static   ok           127.0.0.1/8
lo0/v6            static   ok           ::1/128
igb0/ll           addrconf ok           fe80::eaea:6aff:fe09:7f66%igb0/10
cxgbe0/ll         addrconf ok           fe80::aa40:25ff:fe04:393%cxgbe0/10
cxgbe1/ll         addrconf ok           fe80::aa40:25ff:fe04:39b%cxgbe1/10
tfportint0_0/ll   addrconf ok           fe80::aa40:25ff:febb:13bc%tfportint0_0/10
tfportrear0_0/ll  addrconf ok           fe80::aa40:25ff:febb:13bd%tfportrear0_0/10
[...]
```
