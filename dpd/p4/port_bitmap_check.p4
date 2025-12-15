// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

// Port Bitmap Check Table
//
// Per-port decapsulation filter for multicast egress. Included via
// `#include <port_bitmap_check.p4>` in MulticastEgress (see sidecar.p4).
//
// # Bitmap Structure
//
// 256-port bitmap split across 8 x 32-bit metadata fields:
//
//   decap_ports_0: ports   0-31   (bit N = port N)
//   decap_ports_1: ports  32-63   (bit N = port 32+N)
//   decap_ports_2: ports  64-95   (bit N = port 64+N)
//   decap_ports_3: ports  96-127  (bit N = port 96+N)
//   decap_ports_4: ports 128-159  (bit N = port 128+N)
//   decap_ports_5: ports 160-191  (bit N = port 160+N)
//   decap_ports_6: ports 192-223  (bit N = port 192+N)
//   decap_ports_7: ports 224-255  (bit N = port 224+N)
//
// # Design
//
// The table has const entries mapping each port (0-255) to an action that:
//   1. Selects the correct 32-bit segment (decap_ports_N);
//   2. Bitwise ANDs it with a single-bit mask for that port's position;
//   3. Then, stores result in meta.bitmap_result
//
// Prerequisite: `meta.port_number` is populated by the MulticastEgress
// `asic_id_to_port` table (keyed by `eg_intr_md.egress_port`) prior to
// invoking `port_bitmap_check.apply()`.
//
// If bitmap_result != 0, the port is in the decap set and outer headers
// are stripped (Geneve decapsulation). Otherwise, the packet is forwarded
// with encapsulation intact.
//
// # Use Case
//
// External multicast groups have members on specific sleds. When a multicast
// packet is replicated to all ports in the group, only ports connected to
// member sleds should decapsulate. Other ports (e.g., uplinks forwarding to
// peer switches) keep the Geneve encapsulation.
//
// ## Example
//   Group with members on sleds connected to ports 5, 12, 47
//   decap_ports_0 = 0x00001020  (bits 5 and 12 set)
//   decap_ports_1 = 0x00008000  (bit 15 set = port 47)
//   decap_ports_2..7 = 0x00000000
//   ...

	action check_port_bitmap_0(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_0 & bit_mask;
	}

	action check_port_bitmap_1(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_1 & bit_mask;
	}

	action check_port_bitmap_2(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_2 & bit_mask;
	}

	action check_port_bitmap_3(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_3 & bit_mask;
	}

	action check_port_bitmap_4(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_4 & bit_mask;
	}

	action check_port_bitmap_5(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_5 & bit_mask;
	}

	action check_port_bitmap_6(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_6 & bit_mask;
	}

	action check_port_bitmap_7(bit<32> bit_mask) {
		meta.bitmap_result = meta.decap_ports_7 & bit_mask;
	}

	table port_bitmap_check {
		key = { meta.port_number: exact; }

		actions = {
			check_port_bitmap_0;
			check_port_bitmap_1;
			check_port_bitmap_2;
			check_port_bitmap_3;
			check_port_bitmap_4;
			check_port_bitmap_5;
			check_port_bitmap_6;
			check_port_bitmap_7;
		}

		const entries = {
			// Ports 0-31 - Check against decap_ports_0
			0 : check_port_bitmap_0(32w0x00000001);
			1 : check_port_bitmap_0(32w0x00000002);
			2 : check_port_bitmap_0(32w0x00000004);
			3 : check_port_bitmap_0(32w0x00000008);
			4 : check_port_bitmap_0(32w0x00000010);
			5 : check_port_bitmap_0(32w0x00000020);
			6 : check_port_bitmap_0(32w0x00000040);
			7 : check_port_bitmap_0(32w0x00000080);
			8 : check_port_bitmap_0(32w0x00000100);
			9 : check_port_bitmap_0(32w0x00000200);
			10 : check_port_bitmap_0(32w0x00000400);
			11 : check_port_bitmap_0(32w0x00000800);
			12 : check_port_bitmap_0(32w0x00001000);
			13 : check_port_bitmap_0(32w0x00002000);
			14 : check_port_bitmap_0(32w0x00004000);
			15 : check_port_bitmap_0(32w0x00008000);
			16 : check_port_bitmap_0(32w0x00010000);
			17 : check_port_bitmap_0(32w0x00020000);
			18 : check_port_bitmap_0(32w0x00040000);
			19 : check_port_bitmap_0(32w0x00080000);
			20 : check_port_bitmap_0(32w0x00100000);
			21 : check_port_bitmap_0(32w0x00200000);
			22 : check_port_bitmap_0(32w0x00400000);
			23 : check_port_bitmap_0(32w0x00800000);
			24 : check_port_bitmap_0(32w0x01000000);
			25 : check_port_bitmap_0(32w0x02000000);
			26 : check_port_bitmap_0(32w0x04000000);
			27 : check_port_bitmap_0(32w0x08000000);
			28 : check_port_bitmap_0(32w0x10000000);
			29 : check_port_bitmap_0(32w0x20000000);
			30 : check_port_bitmap_0(32w0x40000000);
			31 : check_port_bitmap_0(32w0x80000000);
			// Ports 32-63 - Check against decap_ports_1
			32 : check_port_bitmap_1(32w0x00000001);
			33 : check_port_bitmap_1(32w0x00000002);
			34 : check_port_bitmap_1(32w0x00000004);
			35 : check_port_bitmap_1(32w0x00000008);
			36 : check_port_bitmap_1(32w0x00000010);
			37 : check_port_bitmap_1(32w0x00000020);
			38 : check_port_bitmap_1(32w0x00000040);
			39 : check_port_bitmap_1(32w0x00000080);
			40 : check_port_bitmap_1(32w0x00000100);
			41 : check_port_bitmap_1(32w0x00000200);
			42 : check_port_bitmap_1(32w0x00000400);
			43 : check_port_bitmap_1(32w0x00000800);
			44 : check_port_bitmap_1(32w0x00001000);
			45 : check_port_bitmap_1(32w0x00002000);
			46 : check_port_bitmap_1(32w0x00004000);
			47 : check_port_bitmap_1(32w0x00008000);
			48 : check_port_bitmap_1(32w0x00010000);
			49 : check_port_bitmap_1(32w0x00020000);
			50 : check_port_bitmap_1(32w0x00040000);
			51 : check_port_bitmap_1(32w0x00080000);
			52 : check_port_bitmap_1(32w0x00100000);
			53 : check_port_bitmap_1(32w0x00200000);
			54 : check_port_bitmap_1(32w0x00400000);
			55 : check_port_bitmap_1(32w0x00800000);
			56 : check_port_bitmap_1(32w0x01000000);
			57 : check_port_bitmap_1(32w0x02000000);
			58 : check_port_bitmap_1(32w0x04000000);
			59 : check_port_bitmap_1(32w0x08000000);
			60 : check_port_bitmap_1(32w0x10000000);
			61 : check_port_bitmap_1(32w0x20000000);
			62 : check_port_bitmap_1(32w0x40000000);
			63 : check_port_bitmap_1(32w0x80000000);
			// Ports 64-95 - Check against decap_ports_2
			64 : check_port_bitmap_2(32w0x00000001);
			65 : check_port_bitmap_2(32w0x00000002);
			66 : check_port_bitmap_2(32w0x00000004);
			67 : check_port_bitmap_2(32w0x00000008);
			68 : check_port_bitmap_2(32w0x00000010);
			69 : check_port_bitmap_2(32w0x00000020);
			70 : check_port_bitmap_2(32w0x00000040);
			71 : check_port_bitmap_2(32w0x00000080);
			72 : check_port_bitmap_2(32w0x00000100);
			73 : check_port_bitmap_2(32w0x00000200);
			74 : check_port_bitmap_2(32w0x00000400);
			75 : check_port_bitmap_2(32w0x00000800);
			76 : check_port_bitmap_2(32w0x00001000);
			77 : check_port_bitmap_2(32w0x00002000);
			78 : check_port_bitmap_2(32w0x00004000);
			79 : check_port_bitmap_2(32w0x00008000);
			80 : check_port_bitmap_2(32w0x00010000);
			81 : check_port_bitmap_2(32w0x00020000);
			82 : check_port_bitmap_2(32w0x00040000);
			83 : check_port_bitmap_2(32w0x00080000);
			84 : check_port_bitmap_2(32w0x00100000);
			85 : check_port_bitmap_2(32w0x00200000);
			86 : check_port_bitmap_2(32w0x00400000);
			87 : check_port_bitmap_2(32w0x00800000);
			88 : check_port_bitmap_2(32w0x01000000);
			89 : check_port_bitmap_2(32w0x02000000);
			90 : check_port_bitmap_2(32w0x04000000);
			91 : check_port_bitmap_2(32w0x08000000);
			92 : check_port_bitmap_2(32w0x10000000);
			93 : check_port_bitmap_2(32w0x20000000);
			94 : check_port_bitmap_2(32w0x40000000);
			95 : check_port_bitmap_2(32w0x80000000);
			// Ports 96-127 - Check against decap_ports_3
			96 : check_port_bitmap_3(32w0x00000001);
			97 : check_port_bitmap_3(32w0x00000002);
			98 : check_port_bitmap_3(32w0x00000004);
			99 : check_port_bitmap_3(32w0x00000008);
			100 : check_port_bitmap_3(32w0x00000010);
			101 : check_port_bitmap_3(32w0x00000020);
			102 : check_port_bitmap_3(32w0x00000040);
			103 : check_port_bitmap_3(32w0x00000080);
			104 : check_port_bitmap_3(32w0x00000100);
			105 : check_port_bitmap_3(32w0x00000200);
			106 : check_port_bitmap_3(32w0x00000400);
			107 : check_port_bitmap_3(32w0x00000800);
			108 : check_port_bitmap_3(32w0x00001000);
			109 : check_port_bitmap_3(32w0x00002000);
			110 : check_port_bitmap_3(32w0x00004000);
			111 : check_port_bitmap_3(32w0x00008000);
			112 : check_port_bitmap_3(32w0x00010000);
			113 : check_port_bitmap_3(32w0x00020000);
			114 : check_port_bitmap_3(32w0x00040000);
			115 : check_port_bitmap_3(32w0x00080000);
			116 : check_port_bitmap_3(32w0x00100000);
			117 : check_port_bitmap_3(32w0x00200000);
			118 : check_port_bitmap_3(32w0x00400000);
			119 : check_port_bitmap_3(32w0x00800000);
			120 : check_port_bitmap_3(32w0x01000000);
			121 : check_port_bitmap_3(32w0x02000000);
			122 : check_port_bitmap_3(32w0x04000000);
			123 : check_port_bitmap_3(32w0x08000000);
			124 : check_port_bitmap_3(32w0x10000000);
			125 : check_port_bitmap_3(32w0x20000000);
			126 : check_port_bitmap_3(32w0x40000000);
			127 : check_port_bitmap_3(32w0x80000000);
			// Ports 128-159 - Check against decap_ports_4
			128 : check_port_bitmap_4(32w0x00000001);
			129 : check_port_bitmap_4(32w0x00000002);
			130 : check_port_bitmap_4(32w0x00000004);
			131 : check_port_bitmap_4(32w0x00000008);
			132 : check_port_bitmap_4(32w0x00000010);
			133 : check_port_bitmap_4(32w0x00000020);
			134 : check_port_bitmap_4(32w0x00000040);
			135 : check_port_bitmap_4(32w0x00000080);
			136 : check_port_bitmap_4(32w0x00000100);
			137 : check_port_bitmap_4(32w0x00000200);
			138 : check_port_bitmap_4(32w0x00000400);
			139 : check_port_bitmap_4(32w0x00000800);
			140 : check_port_bitmap_4(32w0x00001000);
			141 : check_port_bitmap_4(32w0x00002000);
			142 : check_port_bitmap_4(32w0x00004000);
			143 : check_port_bitmap_4(32w0x00008000);
			144 : check_port_bitmap_4(32w0x00010000);
			145 : check_port_bitmap_4(32w0x00020000);
			146 : check_port_bitmap_4(32w0x00040000);
			147 : check_port_bitmap_4(32w0x00080000);
			148 : check_port_bitmap_4(32w0x00100000);
			149 : check_port_bitmap_4(32w0x00200000);
			150 : check_port_bitmap_4(32w0x00400000);
			151 : check_port_bitmap_4(32w0x00800000);
			152 : check_port_bitmap_4(32w0x01000000);
			153 : check_port_bitmap_4(32w0x02000000);
			154 : check_port_bitmap_4(32w0x04000000);
			155 : check_port_bitmap_4(32w0x08000000);
			156 : check_port_bitmap_4(32w0x10000000);
			157 : check_port_bitmap_4(32w0x20000000);
			158 : check_port_bitmap_4(32w0x40000000);
			159 : check_port_bitmap_4(32w0x80000000);
			// Ports 160-191 - Check against decap_ports_5
			160 : check_port_bitmap_5(32w0x00000001);
			161 : check_port_bitmap_5(32w0x00000002);
			162 : check_port_bitmap_5(32w0x00000004);
			163 : check_port_bitmap_5(32w0x00000008);
			164 : check_port_bitmap_5(32w0x00000010);
			165 : check_port_bitmap_5(32w0x00000020);
			166 : check_port_bitmap_5(32w0x00000040);
			167 : check_port_bitmap_5(32w0x00000080);
			168 : check_port_bitmap_5(32w0x00000100);
			169 : check_port_bitmap_5(32w0x00000200);
			170 : check_port_bitmap_5(32w0x00000400);
			171 : check_port_bitmap_5(32w0x00000800);
			172 : check_port_bitmap_5(32w0x00001000);
			173 : check_port_bitmap_5(32w0x00002000);
			174 : check_port_bitmap_5(32w0x00004000);
			175 : check_port_bitmap_5(32w0x00008000);
			176 : check_port_bitmap_5(32w0x00010000);
			177 : check_port_bitmap_5(32w0x00020000);
			178 : check_port_bitmap_5(32w0x00040000);
			179 : check_port_bitmap_5(32w0x00080000);
			180 : check_port_bitmap_5(32w0x00100000);
			181 : check_port_bitmap_5(32w0x00200000);
			182 : check_port_bitmap_5(32w0x00400000);
			183 : check_port_bitmap_5(32w0x00800000);
			184 : check_port_bitmap_5(32w0x01000000);
			185 : check_port_bitmap_5(32w0x02000000);
			186 : check_port_bitmap_5(32w0x04000000);
			187 : check_port_bitmap_5(32w0x08000000);
			188 : check_port_bitmap_5(32w0x10000000);
			189 : check_port_bitmap_5(32w0x20000000);
			190 : check_port_bitmap_5(32w0x40000000);
			191 : check_port_bitmap_5(32w0x80000000);
			// Ports 192-223 - Check against decap_ports_6
			192 : check_port_bitmap_6(32w0x00000001);
			193 : check_port_bitmap_6(32w0x00000002);
			194 : check_port_bitmap_6(32w0x00000004);
			195 : check_port_bitmap_6(32w0x00000008);
			196 : check_port_bitmap_6(32w0x00000010);
			197 : check_port_bitmap_6(32w0x00000020);
			198 : check_port_bitmap_6(32w0x00000040);
			199 : check_port_bitmap_6(32w0x00000080);
			200 : check_port_bitmap_6(32w0x00000100);
			201 : check_port_bitmap_6(32w0x00000200);
			202 : check_port_bitmap_6(32w0x00000400);
			203 : check_port_bitmap_6(32w0x00000800);
			204 : check_port_bitmap_6(32w0x00001000);
			205 : check_port_bitmap_6(32w0x00002000);
			206 : check_port_bitmap_6(32w0x00004000);
			207 : check_port_bitmap_6(32w0x00008000);
			208 : check_port_bitmap_6(32w0x00010000);
			209 : check_port_bitmap_6(32w0x00020000);
			210 : check_port_bitmap_6(32w0x00040000);
			211 : check_port_bitmap_6(32w0x00080000);
			212 : check_port_bitmap_6(32w0x00100000);
			213 : check_port_bitmap_6(32w0x00200000);
			214 : check_port_bitmap_6(32w0x00400000);
			215 : check_port_bitmap_6(32w0x00800000);
			216 : check_port_bitmap_6(32w0x01000000);
			217 : check_port_bitmap_6(32w0x02000000);
			218 : check_port_bitmap_6(32w0x04000000);
			219 : check_port_bitmap_6(32w0x08000000);
			220 : check_port_bitmap_6(32w0x10000000);
			221 : check_port_bitmap_6(32w0x20000000);
			222 : check_port_bitmap_6(32w0x40000000);
			223 : check_port_bitmap_6(32w0x80000000);
			// Ports 224-255 - Check against decap_ports_7
			224 : check_port_bitmap_7(32w0x00000001);
			225 : check_port_bitmap_7(32w0x00000002);
			226 : check_port_bitmap_7(32w0x00000004);
			227 : check_port_bitmap_7(32w0x00000008);
			228 : check_port_bitmap_7(32w0x00000010);
			229 : check_port_bitmap_7(32w0x00000020);
			230 : check_port_bitmap_7(32w0x00000040);
			231 : check_port_bitmap_7(32w0x00000080);
			232 : check_port_bitmap_7(32w0x00000100);
			233 : check_port_bitmap_7(32w0x00000200);
			234 : check_port_bitmap_7(32w0x00000400);
			235 : check_port_bitmap_7(32w0x00000800);
			236 : check_port_bitmap_7(32w0x00001000);
			237 : check_port_bitmap_7(32w0x00002000);
			238 : check_port_bitmap_7(32w0x00004000);
			239 : check_port_bitmap_7(32w0x00008000);
			240 : check_port_bitmap_7(32w0x00010000);
			241 : check_port_bitmap_7(32w0x00020000);
			242 : check_port_bitmap_7(32w0x00040000);
			243 : check_port_bitmap_7(32w0x00080000);
			244 : check_port_bitmap_7(32w0x00100000);
			245 : check_port_bitmap_7(32w0x00200000);
			246 : check_port_bitmap_7(32w0x00400000);
			247 : check_port_bitmap_7(32w0x00800000);
			248 : check_port_bitmap_7(32w0x01000000);
			249 : check_port_bitmap_7(32w0x02000000);
			250 : check_port_bitmap_7(32w0x04000000);
			251 : check_port_bitmap_7(32w0x08000000);
			252 : check_port_bitmap_7(32w0x10000000);
			253 : check_port_bitmap_7(32w0x20000000);
			254 : check_port_bitmap_7(32w0x40000000);
			255 : check_port_bitmap_7(32w0x80000000);
		}

		const size = 256;
	}
