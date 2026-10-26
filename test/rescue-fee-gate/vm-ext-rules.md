# Variable-length instructions: the C++ VM's rules

The C++ VM (`crypto/vm/opctable.cpp`) looks up at most 24 bits of code, padded with zeros, and
runs the instruction whose range holds them. For a variable-length (Ext) instruction it then:

1. charges `10 + header` gas, checked at once from version 4 (out of gas ends the VM here,
   before anything below);
2. requires the header bits to be present, or raises invalid opcode (6);
3. calls the instruction's function, which checks its data bits, then its references, each
   short one raising invalid opcode (6) with no further gas, and only then takes its operands
   from the stack.

Data bits are not charged. Where the data is a slice, its completion tag (the last 1 bit and the
zeros after it) is removed; data without a 1 bit becomes an empty slice. `a` is the argument in
the header's low bits.

| Opcode | Instruction | Header bits | Data bits | References | Notes |
|---|---|---|---|---|---|
| `82` | PUSHINT (long) | 13 | 3 + 8 × ((a & 31) + 2) | 0 | a = 31 is unassigned |
| `88` `89` `8A` | PUSHREF, PUSHREFSLICE, PUSHREFCONT | 8 | 0 | 1 | |
| `8B` | PUSHSLICE | 12 | 8 × (a & 15) + 4 | 0 | tag removed |
| `8C` | PUSHSLICE | 15 | 8 × (a & 31) + 1 | ((a >> 5) & 3) + 1 | tag removed |
| `8D` | PUSHSLICE | 18 | 8 × (a & 127) + 6 | (a >> 7) & 7 | a < 640; tag removed |
| `8E` `8F` | PUSHCONT | 16 | 8 × (a & 127) | (a >> 7) & 3 | |
| `9x` | PUSHCONT (short) | 8 | 8 × (a & 15) | 0 | |
| `CF20` `CF21` | STREFCONST, STREF2CONST | 16 | 0 | (a & 1) + 1 | then the builder |
| `CF8` | STSLICECONST | 14 | 8 × (a & 7) + 2 | (a >> 3) & 3 | tag removed; then the builder |
| `D728` | SDBEGINS, SDBEGINSQ | 21 | 8 × (a & 127) + 3 | 0 | tag removed; a & 128 is quiet |
| `DB3C`–`DB3E` | CALLREF, JMPREF, JMPREFDATA | 16 | 0 | 1 | |
| `E300`–`E303`, `E30D`, `E30E` | IFREF and the like | 16 | 0 | 1 | then the condition |
| `E30F` | IFREFELSEREF | 16 | 0 | 2 | then the condition |
| `E3C` | IFBITJMPREF, IFNBITJMPREF | 16 | 0 | 1 | then the integer |
| `F4A4`–`F4A7`, `F4AC`–`F4AF` | DICTPUSHCONST, PFXDICTSWITCH | 24 | 0 | 1 | the header ends with the root bit and 10 key bits |
| `FEF` | DEBUGSTR | 16 | 8 × ((a & 15) + 1) | 0 | skipped: a node runs with debug opcodes disabled |

`vm_ext_scenarios.py` runs every family on both VMs with its data and references complete, one
data bit short, one reference short, data without a completion tag, and the budget one below
and at the header's base gas with the data complete and one bit short, on an empty stack and
after pushing the operands it takes.
