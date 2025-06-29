## LDEFS file
straightforward; just basic info about the architecture
- Big endian
- 8-bit
- names of processor, files, etc.

## PSPEC file
Was a little confusing, but I referenced the `x86.pspec` file and also someone else's work:
- https://github.com/beardypig/ghidra-chip8/blob/master/data/languages/chip8.pspec
	- I don't think he fully defined all of the registers, although maybe they aren't all fully necessary to define; will find out later

I defined all the registers:
- PC
- I
- SP
- DT
- ST
- V0-VF
```
  <!-- Program counter register (16-bit) -->
  <programcounter register="PC"/>
  <register_data>
    <!-- Index register (16-bit) -->
    <register name="I">
    <!-- Stack pointer (8-bit) -->
    <register name="SP">
    <!-- Delay and sound timers (8-bit) -->
    <register name="DT">
    <register name="ST">
    <!-- General purpose registers (8-bit) -->
    <register name="V0">
    <register name="V1">
    <register name="V2">
    <register name="V3">
    <register name="V4">
    <register name="V5">
    <register name="V6">
    <register name="V7">
    <register name="V8">
    <register name="V9">
    <register name="VA">
    <register name="VB">
    <register name="VC">
    <register name="VD">
    <register name="VE">
    <register name="VF">
  </register_data>
```

Then also defined the static fontset sprites:
- 0 through F; 5 bytes each
```
  <default_symbols>
    <symbol name="_start" address="ram:0x200" entry="true"/>
    <!-- Font set -->
    <symbol name="FONTSET_0" address="ram:0x000"/>
    <symbol name="FONTSET_1" address="ram:0x005"/>
    <symbol name="FONTSET_2" address="ram:0x00a"/>
    <symbol name="FONTSET_3" address="ram:0x00f"/>
    <symbol name="FONTSET_4" address="ram:0x014"/>
    <symbol name="FONTSET_5" address="ram:0x019"/>
    <symbol name="FONTSET_6" address="ram:0x01e"/>
    <symbol name="FONTSET_7" address="ram:0x023"/>
    <symbol name="FONTSET_8" address="ram:0x028"/>
    <symbol name="FONTSET_9" address="ram:0x02d"/>
    <symbol name="FONTSET_A" address="ram:0x032"/>
    <symbol name="FONTSET_B" address="ram:0x037"/>
    <symbol name="FONTSET_C" address="ram:0x03c"/>
    <symbol name="FONTSET_D" address="ram:0x041"/>
    <symbol name="FONTSET_E" address="ram:0x046"/>
    <symbol name="FONTSET_F" address="ram:0x04b"/>
  </default_symbols>
```

Then defined regions of memory:
- 0x000 to 0x04F - fontset
- 0x050 to 0x14F - stack region (16 16-bit entries)
- 0x200 to 0xFFF - ROM program region
```
  <default_memory_blocks>
    <memory_block name="FONTSET" start_address="ram:0x000" length="0x50"/>
    <memory_block name="STACK" start_address="ram:0x050" length="0x100"/>
    <memory_block name="PROGRAM" start_address="ram:0x200" length="0xe00"/>
  </default_memory_blocks>
```
this section in particular I didn't see in `x86.pspec` or some of the other `.pspec` files I looked at, so I'm not sure if this is actually necessary to define here; I guess doesn't hurt to have more well-though-out definitions at this point

## CSPEC file
OK for this file I'm quite confused.

The compiler specification should describe compiler info;
- how memory is addressed
- size of pointers
- global definitions
- etc.

I'm specifically looking at `x86-64-gcc.cspec`, which is definitely more detailed than I think I need

I think I understand the first parts (I will just add what I think I need for now and then test and see if I need to change anything afterwards)

(here's what my initial thoughts are):
```
<compiler_spec>
  <data_organization>
	<pointer_size value="2" />
  </data_organization>
  <global>
    <range space="ram"/>
  </global>
  <stackpointer register="SP" space="ram"/>
  ...
</compiler_spec>
```

But I'm not understanding the `prototype` sections;

6/29: reading up on it here: https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/compiler_spec/index.html

which I believe is the documentation from https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/doc/cspec.xml originally

seems like the documentation for this part is pretty good actually, will read through it