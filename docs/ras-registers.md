# RAS Registers

## Address Calculation

Base formula

```
0x4000000 + pipe*0x1000000 + stage*0x80000 + block_offset + reg_offset
```

- Pipes: 0-3
- Stages: 0-19
- Tofino2 has 12 SRAM rows per stage (0-11)

## TCAM Parity Error Latch

Register: intr_status_mau_tcam_array
Block offset: 0x40800 (tcams)
Register offset: 0x640

### All 20 stages, pipe 0
```bash
for s in $(seq 0 19); do
  addr=$(printf "0x%x" $((0x4000000 + s*0x80000 + 0x40800 + 0x640)))
  echo "Pipe 0 Stage $s TCAM: $(tftool reg read $addr)"
done
```

### All 20 stages, pipe 1
```bash
for s in $(seq 0 19); do
  addr=$(printf "0x%x" $((0x5000000 + s*0x80000 + 0x40800 + 0x640)))
  echo "Pipe 1 Stage $s TCAM: $(tftool reg read $addr)"
done
```

Bits: 16-bit, one bit per TCAM column pair (8 pairs)

## SRAM (Unit RAM) ECC Error Latch

Register: intr_status_mau_unit_ram_row
Block offset: 0x68000 (rams.array) + row*0x1000
Register offset: 0xF30

### Stages 10-12, all 12 rows, pipe 0
```bash
for s in 10 11 12; do
  for r in $(seq 0 11); do
    addr=$(printf "0x%x" $((0x4000000 + s*0x80000 + 0x68000 + r*0x1000 + 0xF30)))
    echo "Pipe 0 Stage $s Row $r SRAM: $(tftool reg read $addr)"
  done
done
```

Bits: 24-bit
- Bits 0-11: SBE (single-bit errors) columns 0-11
- Bits 12-23: MBE (multi-bit errors) columns 0-11

## Quick Reference - Key Addresses (Pipe 0)

```
┌───────┬─────────────┬───────────────────┐
│ Stage │ TCAM Status │ SRAM Row 0 Status │
├───────┼─────────────┼───────────────────┤
│ 10    │ 0x4540E40   │ 0x4568F30         │
├───────┼─────────────┼───────────────────┤
│ 11    │ 0x45C0E40   │ 0x45E8F30         │
├───────┼─────────────┼───────────────────┤
│ 12    │ 0x4640E40   │ 0x4668F30         │
└───────┴─────────────┴───────────────────┘
```

For pipe 1, add 0x1000000 to all addresses.
