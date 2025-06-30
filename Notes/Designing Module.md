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

This is what I've gathered about compiler spec (`.cspec`) files:
- always has `<compiler_spec>` as the root XML tag
- All specific compiler features are described using subtags to this tag
- all the subtags are optional except the `<default_prototype>` tag

`varnode` tags;
- again; varnodes are "generalizations of either a register or a memory location"
- defining triple for a varnode: an _address space_, an _offset_ and a _size_
- there are really two different XML tags that are used to describe varnodes and both are referred to as a `varnode tag`
	- `register` tag
		- only requires `name`
	- `varnode` tag
		- requires `space`, `offset`, and `size`

`data_organization` section
- provides information about the sizes of core datatypes and how the compiler typically aligns datatypes
- Most atomic datatypes get their alignment information from the `<size_alignment_map>`. If the size of a particular datatype isn't listed in the map, the `<default_alignment>` value will be used.
- `<default_alignment>`
	- (Optional) Default alignment for any datatype that isn't structure, union, array, or pointer and whose size isn't in the size/alignment map
- `<pointer_size>`
	- (Optional) Size of a pointer

`<global>` tag 
- marks specific memory regions as storage locations for the compiler's global variables

`<readonly>` tag 
- labels a specific region as read-only
- i *might* use this for 0x000 to 0x50 (font set); but maybe unnecessary

`<stackpointer>`
- informs Ghidra of the main stack mechanism for the compiler

`<returnaddress>`
- describes how the return address is stored, upon entry to a function

Also there are a ton of other tags I briefly looked over and I don't think I care about them (at least for now, in this initial attempt) for my processor:
- `context_data` (`context_set` and `tracked_set`): allow certain values to be assumed by compiler analysis
- `callfixup`: optimizations for internal compiler functions
	- involves writing P-code
- `prefersplit`: mark specific registers as packed, containing multiple logical values that need to be split
- `aggressivetrim`: lets the decompiler be more aggressive when use of the extended bytes is more indeterminate
- `<nohighptr>`: describes a memory region into which the compiler does not expect to see pointers from any high-level source code
- etc.

Most important though is the following;

#### Parameter Passing
https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/compiler_spec/cspec_parampass.html

A *prototype model*, in Ghidra, is a set of rules for determining how parameters and return values are passed between a function and its subfunction

For a high-level language (such as C or Java), a function prototype is:
- ordered list of parameters (each specified as a name and a datatype) that are passed to the function as input 
- plus the optional value (specified as just a datatype) returned by the function
A prototype model specifies how a compiler decides which storage locations are used to hold the actual values at run time

Ghidra also needs to solve the inverse problem: 
- given a set of storage locations (registers and stack locations) that look like they are inputs and outputs to a function, 
- determine a high-level function prototype that produces those locations when compiled

`<prototype>` tag encodes details about a specific prototype model, within a compiler specification
- All `<prototype>` tags must include the subtags, `<input>` and `<output>`
	- `<input>` tag holds the resources used to pass input parameters
	- `<output>` describes resources for return value storage
	- A resource is described by the `<pentry>` tag
		- Most `<pentry>` tags describe a storage location to be used by a single variable
		- If the tag has an _align_ attribute however, multiple variables can be allocated from the same resource
		- How `<pentry>` resources are used is determined by the prototype model's _strategy_
			- currently only two strategies: _standard_ and _register_
			- If the attribute is not present, the prototype model defaults to the _standard_ strategy

