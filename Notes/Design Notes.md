# Design Notes

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
```xml
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

#### `<prototype>` tag
`<prototype>` tag encodes details about a specific prototype model, within a compiler specification
- All `<prototype>` tags must include the subtags, `<input>` and `<output>`
	- `<input>` tag holds the resources used to pass input parameters
	- `<output>` describes resources for return value storage
	- A resource is described by the `<pentry>` tag
		- Most `<pentry>` tags describe a storage location to be used by a single variable
		- If the tag has an _align_ attribute however, multiple variables can be allocated from the same resource

`<prototype>` also has a few necessary attributes:
- `name` (obvious)
- `extrapop`: Amount stack pointer changes across a call or _unknown_
- `stackshift`: Amount stack changes due to the call mechanism

`extrapop` specifies the number of bytes a called function (a "callee") removes from the stack _in addition to_ the return address before it returns
- will usually match the size of the stack-pointer, indicating that a called function usually pops the return value itself and changes the stack pointer in a way not apparent in the (callers) p-code
- The attribute can also be specified as `unknown`; "This turns on the fairly onerous analysis associated with the Microsoft _stdcall_ calling convention, where functions, upon return, pop off their own stack parameters in addition to the return address"

`stackshift` indicates the amount the stack pointer changes just due to the call mechanism used to access a function with this prototype
- call instruction for many processors pushes the return address onto the stack
- typically be 2, 4, or 8, matching the code address size

How `<pentry>` resources are used is determined by the prototype model's _strategy_
- currently only two strategies: _standard_ and _register_
- If the attribute is not present, the prototype model defaults to the _standard_ strategy

`standard` strategy is:
- default approach
- the `<pentry>` subtags under the `<input>` tag are ordered resource list of storage locations
- decompiler assigns the first parameter to the first location in the list, the second parameter to the second, and so on, until all available registers are used, after which it typically assigns remaining parameters to the stack
- expects a strict, sequential use of resources

`register` strategy is:
- does not rely on a fixed order of resources
- treats the `<pentry>` tags as a _pool_ of available parameter locations
- behaves in the same way as the `standard` strategy, except that in the reverse case, the decompiler does not care about gaps in the resource list;
	- more flexible and is designed to handle non-standard or heavily optimized calling conventions where registers may be used in an arbitrary order

For more clarity, I asked Gemini for an explanation;

## Hypothetical architecture for explanation
Imagine a hypothetical 32-bit processor with a calling convention defined in a `.cspec` file. This convention dictates that the first four integer parameters are passed in registers `R0`, `R1`, `R2`, and `R3`, in that specific order.

Here is the `<prototype>` definition in the `.cspec` file:

```xml
<prototype name="my_standard_abi" strategy="standard" extrapop="0" stackshift="0">
  <input>
    <pentry minsize="1" maxsize="4">
      <register name="R0"/>  <!-- 1st parameter goes here -->
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="R1"/>  <!-- 2nd parameter goes here -->
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="R2"/>  <!-- 3rd parameter goes here -->
    </pentry>
    <pentry minsize="1" maxsize="4">
      <register name="R3"/>  <!-- 4th parameter goes here -->
    </pentry>
  </input>
  <output>
    <pentry minsize="1" maxsize="4">
      <register name="R0"/> <!-- Return value goes here -->
    </pentry>
  </output>
</prototype>
```
Now, let's consider two scenarios for a function that is intended to have three parameters.

### Scenario 1: The Ideal Case (No Gaps)
A compiler generates code for the following function:  
`void process_data(int id, int value, int flags);`

Following the `my_standard_abi` convention correctly, the compiler assigns the parameters as follows:
- `id` is passed in register **`R0`**.
- `value` is passed in register **`R1`**.
- `flags` is passed in register **`R2`**.

**How Ghidra Decompiles This:**
1. Ghidra analyzes the function's machine code and sees that registers `R0`, `R1`, and `R2` are read by the function before they are written to (they are "live" inputs).
2. It consults the `<prototype>` named `my_standard_abi`.
3. It checks the **first** `<pentry>`: is `R0` used as an input? **Yes**. It identifies this as the first parameter.
4. It checks the **second** `<pentry>`: is `R1` used as an input? **Yes**. It identifies this as the second parameter.
5. It checks the **third** `<pentry>`: is `R2` used as an input? **Yes**. It identifies this as the third parameter.
6. It checks the **fourth** `<pentry>`: is `R3` used as an input? **No**. It stops looking.

The decompilation is successful, resulting in a correct signature: `void process_data(int param_1, int param_2, int param_3)`

### Scenario 2: The Problem Case (With a "Gap")
Now, imagine the same function, but an optimizing compiler realizes that the `id` parameter is never actually used inside the function. To save an instruction, it generates code that calls `process_data` but only loads `value` and `flags`. 

The assignments are now:
- `R0` is **unused**.
- `value` is passed in register **`R1`**.
- `flags` is passed in register **`R2`**.

This creates a "gap" in the expected parameter sequence.

**How Ghidra Decompiles This:**
1. Ghidra analyzes the function's machine code and sees that registers `R1` and `R2` are used as inputs. `R0` is not.
2. It consults the same `my_standard_abi` prototype.
3. It checks the **first** `<pentry>`: is `R0` used as an input? **No**.
4. Because the very first entry in its ordered list was not met, the `standard` strategy **stops immediately**. It assumes that if the first parameter slot is empty, no subsequent slots can be filled. It does not proceed to check `R1` or `R2`.

The decompilation fails to identify any parameters, resulting in an incorrect signature: `void process_data(void)`. The decompiler sees that `R1` and `R2` are used, but because the calling convention's strict rules were violated, it cannot correctly map them to the function's signature.

#### What This Means for Decompilation
The **`standard`** strategy is fundamentally rigid. It works perfectly for code that strictly adheres to a well-defined Application Binary Interface (ABI), which is why it is the default. However, it is brittle when dealing with optimized code or custom calling conventions that might skip register assignments. This is the key difference from the `register` strategy, which would have correctly identified `R1` and `R2` as parameters in the second scenario because it treats the `<pentry>` list as a flexible pool rather than a strict sequence.

## Now `prototype` for CHIP-8
Since "function calls" in CHIP-8 architecture don't really exist (they're just subroutines), it doesn't make sense to have `input`/`output` for this ISA

Essentially the `call` (`0x2NNN`) instruction pushes the return address onto the stack, and the `ret` (`0x00EE`) instruction pops the address from the stack and jumps to it

Additionally, calling convention for arguments are up to the user; nothing is defined in specification, except that everything uses registers, and no arguments are passed to the stack

So with this in mind (`CALL` pushes exactly one 2-byte address, `RET` pops exactly one 2-byte address, and parameters are not passed on stack), design choices are as follows:
- `extrapop = 0` because amount of extra data popped is always zero
- `stackshift = 2` because 2-byte addresses,
- `strategy = "register"` because calling convention is user-defined; not strictly defined (i.e. people can do whatever they decide for arguments)
- no `input` and no `output` for same reason; calling convention is user-defined
```xml
<default_proto>
    <prototype name="default" extrapop="0" stackshift="2" strategy="register">
      <input/>
      <output/>
    </prototype>
  </default_proto>
```

## SLASPEC and SINC files

Referencing `skel.slaspec` for how to do this (I tried looking at `x86.slaspec` and it seems more complex, referencing a bunch of `.sinc` files)

Using these references:
1. https://github.com/joeferg425/ghidra_proc_spec?tab=readme-ov-file
2. https://github.com/beardypig/ghidra-chip8/blob/master/data/languages/chip8.slaspec
3. https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-1.html#the-language-specification
4. https://ghidra.re/ghidra_docs/languages/html/sleigh_definitions.html

OK so I read through the specification ([resource #4](https://ghidra.re/ghidra_docs/languages/html/sleigh_definitions.html)) and took notes in [[Ghidra SLEIGH]]; 

The following is notes on each CHIP-8 instruction's SLEIGH code

SYS instruction
```
# 0nnn - SYS addr; Jump to a machine code routine at addr
:SYS addr is opcode=0x0 & nnn {
    goto addr;
}
```
- `SYS` instruction requires opcode = `0` and `nnn` to exist
- we define `addr` as a local operand, which gets its definition from `nnn`;
	- this works because the SLEIGH compiler links the local operands from the display section (i.e. `addr`) to the unbound global fields in the pattern section (i.e. `nnn`) based on their order of appearance; i.e. `nnn` gets "bound" to `addr`
	- `opcode=0x0` is a constraint, not a global operand being bound

CLS instruction
```
# 00E0 - CLS; Clear the display
:CLS is opcode=0x0 & nnn=0x0E0 {
    clear_screen();
}
```
- defined a `pcodeop`; essentially a blackbox to Ghidra (Ghidra doesn't know about its implementation, nor does it need to)

RET instruction
actually found a pretty good example for a 32bit arch in the SLEIGH docs: https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html (section 7.7.2.5); difference is that CHIP-8 stack is growing up instead of down (so operations are inverse)
```
# 00EE - RET; Return from a subroutine
:RET is opcode_full=0x00EE {
	SP = SP - 2;
    local tmp:2 = *:2 SP;
	return [tmp];
}
```
- The specification says "set PC, then subtract 1" but I think it doesn't really make sense to do that; it should be the opposite
	- say we start off with stack at `0x50`; when we do a call, we don't add first and then put the address (because then we'd just be wasting an index; i.e. the first index would just never get used)
	- so I think we actually want to do the inverse; when returning, we subtract first and THEN return
- Also another thing I considered when designing the `CALL`/`RET` instructions; I am making the stack pointer (`SP`) essentially act as a direct reference to the stack, rather than an index
	- I considered making it an index into the 16-slot stack (because that's what the specification suggests) and calculating an offset with a `STACK_BASE` but I think that makes it less readable 
		- ok now i realize this was actually not what the spec said and I'm just being stupid
		- BUT I think i still need to make `SP` 16-bit? otherwise I could just have it assume it's in the lower address space (i.e. first 4 bits of addr assumed to be `0b0000`)
	- So instead, `SP` when dereferenced directly will hold the stack entry it is currently looking at
	- This does mean that I have to make `SP` a 16-bit register instead of the 8-bit like the specification suggests ("can be 8-bit") 
- I am being overly verbose when defining this; `local tmp:2 = *:2 SP;` I could technically just do `return [*:2 SP];` 

JP instruction
```
# 1nnn - JP addr; Jump to location nnn
:JP addr is opcode=0x1 & nnn {
    goto addr;
}
```
- same as SYS

CALL instruction
```
# 2nnn - CALL addr; Call subroutine at nnn
:CALL addr is opcode=0x2 & nnn {
    *:2 SP = addr;
    SP = SP + 2;
    call addr;
}
```
- again, spec says increment first and THEN push to stack; that logic doesn't make sense to me

SE instruction (byte comparison)
```
:SE Vx, byte is opcode=0x3 & x & kk {
    if (Vx == byte) goto (inst_next + 2);
}
```
- apparently `inst_next` is a symbol predefined to be equal to the address of the following instruction
- other than this, for these next couple instructions, only thing I learned was that it is acceptable to reuse the same mnemonic so long as the operands are different (it can differentiate between registers and immediate values given context)

SNE (byte) and SE (register) instructions
```
# 4xkk - SNE Vx, byte; Skip next instruction if Vx != kk
:SNE Vx, byte is opcode=0x4 & x & kk {
    if (Vx != byte) goto (inst_next + 2);
}

# 5xy0 - SE Vx, Vy; Skip next instruction if Vx = Vy
:SE Vx, Vy is opcode=0x5 & x & y {
    if (Vx == Vy) goto (inst_next + 2);
}
```
- nothing new here

The next instructions up until this ADD are self-explanatory;
ADD Vx Vy
```
:ADD Vx, Vy is opcode=0x8 & x & y & n=0x4 {
    Vx = Vx + Vy;
    local flag:1 = carry(Vx, Vy);
    set_flag(flag);
}
```
- `carry(v0, v1)` is a SLEIGH operator that is "True if adding v0 and v1 would produce an unsigned carry"
- For this, we perform the operation FIRST, and then calculate the flag
I defined this macro for setting flag:
```
macro set_flag(value) {
    VF = value:1;
}
```

SUB Vx Vy
```
# 8xy5 - SUB Vx, Vy; Set Vx = Vx - Vy, set VF = NOT borrow
:SUB Vx, Vy is opcode=0x8 & x & y & n=0x5 {
    Vx = Vx - Vy;
    local flag:1 = Vx > Vy;
    set_flag(flag);
}
```
- "NOT borrow" = in subtraction, a "borrow" is needed when a larger number is subtracted from a smaller one
- SUBN basically same instruction just inverse (Vy - Vx instead of Vx - Vy)
- For these, we calculate flag FIRST, then perform the operation

SHR
```
# 8xy6 - SHR Vx {, Vy}; Set Vx = Vx SHR 1
:SHR Vx, Vy is opcode=0x8 & x & y & n=0x6 {
    local flag:1 = Vx & 1;
    set_flag(flag);
    Vx = Vx >> 1;
}
```
- according to spec: "If the least-significant bit of Vx is 1, then VF is set to 1, otherwise 0. Then Vx is divided by 2."
- SHL same but opposite
- For these, we calculate flag FIRST, then perform the operation
- Also, I'm not sure what `Vy`'s involvement in these instructions are

LD `I` addr
```
# Annn - LD I, addr; Set I = nnn
:LD I, addr is opcode=0xA & nnn {
    I = zext(addr);
}
```
- only thing to really note here is `zext(addr)`; without `zext` I believe it is done implicitly, but it is more verbose to add it here

JP V0, addr
```
# Bnnn - JP V0, addr; Jump to location nnn + V0
:JP V0, addr is opcode=0xB & nnn {
    local tmp:2 = zext(addr) + zext(V0);
    goto tmp;
}
```
- this is the same thing, only thing is we are `zext()`'ing the 8-bit `V0` and the 12-bit `nnn`

RND Vx, byte
```
# Cxkk - RND Vx, byte; Set Vx = random byte AND kk
:RND Vx, byte is opcode=0xC & kk {
    local tmp:1 = rand() & kk;
    Vx = tmp;
}
```
need to define a custom `rand` operator; Ghidra doesn't care about the implementation (Ghidra treats `pcodeop`'s as black boxes)
```
define pcodeop rand;
```

SKP and SKNP instructions
```
# Ex9E - SKP Vx; Skip next instruction if key with the value of Vx is pressed
:SKP Vx is opcode=0xE & x & kk=0x9E {
    local key_press:1 = get_key_press();
    if (key_press == Vx) goto (inst_next + 2);
}

# ExA1 - SKNP Vx; Skip next instruction if key with the value of Vx is not pressed
:SKNP Vx is opcode=0xE & x & kk=0xA1 {
    local key_press:1 = get_key_press();
    if (key_press != Vx) goto (inst_next + 2);
}
```
I added a `pcodeop` (again, black box so Ghidra doesn't care) to get the current key pressed;
```
define pcodeop get_key_press;
```

DRW
This is probably the most complicated instruction in actual implementation, but since Ghidra just treats everything as a black box, we can just `define pcodeop` and not care about it
```
# Dxyn - DRW Vx, Vy, nibble; Display n-byte sprite starting at memory location I at (Vx, Vy), set VF = collision
:DRW Vx, Vy, nibble is opcode=0xD & x & y & n & I {
    local flag:1 = draw_sprite(I, Vx, Vy, nibble);
    set_flag(flag);
}
```
and we just define:
```
define pcodeop draw_sprite;
```

Key-related instructions;

considering defining a `wait_for_key` operation

LD "F"
```
# Fx29 - LD F, Vx; Set I = location of sprite for digit Vx
:LD "F", Vx is opcode=0xF & x & kk=0x29 {
    local fontset_addr:2 = zext(Vx) * 5;
    I = fontset_addr;
}
```
- `0x0` is the starting address of the fontset in CHIP-8; each sprite is 5 bytes so multiply by 5
- `"F"` is a string literal that is shown in the instruction; not an argument

LD "B"
```
# Fx33 - LD B, Vx; Store BCD representation of Vx in memory locations I, I+1, and I+2
:LD "B", Vx is opcode=0xF & x & kk=0x33 {
    local hundreds = Vx / 100;
    local tens = (Vx / 10) % 10;
    local ones = Vx % 10;

    *:1 I = hundreds;
    *:1 (I+1) = tens;
    *:1 (I+2) = ones;
}
```
Representation of what's going on in memory: (if `I` is at `0x1000` and `Vx` has value `234`)
```
 Address | Value (Decimal) | Value (8-bit Binary)
+--------+-----------------+----------------------+
|  ...   |       ...       |         ...          |
+--------+-----------------+----------------------+
|  1000  |         2       |       00000010       |  <-- Hundreds digit
+--------+-----------------+----------------------+
|  1001  |         3       |       00000011       |  <-- Tens digit
+--------+-----------------+----------------------+
|  1002  |         4       |       00000100       |  <-- Ones digit
+--------+-----------------+----------------------+
|  ...   |       ...       |         ...          |
+--------+-----------------+----------------------+
```

LD `I`, `Vx`; Store registers V0 through Vx in memory starting at location I
- we need to create 16 different constructors

same for the read instr:
LD `Vx`, `I`; Read registers V0 through Vx from memory starting at location I

OK I AM NOT REALLY SURE IF THIS ALL WORKS BECAUSE I HAVEN'T TESTED IT YET BUT EVERYTHING IS WRITTEN SO FAR SO... idk I'll see about it later in the week

also I'm skipping `opinion` file for now (and likely forever) because it seems unnecessary for my simple ISA

## Fixing everything
OK first thing was that you can't jump to an arithmetic operation:
```
if (...) goto (inst_next + 2);
```
instead need to do this;
```
local inst_after:2 = inst_next + 2;
if (...) goto inst_after;
```
- Third thing is that actually this doesn't work either and I need to find another workaround (TBD):
```
     [java] chip8.slaspec:82: varnode_symbol 'inst_after' (defined at chip8.slaspec:81) is wrong type (should be start, end, or operand) in goto destination
```


Second thing is that I'm stupid; the `attach` mechanism is to attach additional context to already-defined variables; not define new ones
```
attach variables [ Vx Vy ] [ V0 V1 V2 V3 V4 V5 V6 V7 V8 V9 VA VB VC VD VE VF ];
```
since I like having `Vx` and `Vy`, I'm just gonna rename the definition of the token to this:
```
define token instr (16)
    opcode_full = (0,15)        # The full 16-bit instruction (some instructions interpret all)
    opcode      = (12,15)       # Opcode: Highest 4 bits
    nnn         = (0,11)        # nnn or addr: A 12-bit value, the lowest 12 bits of the instruction
    n           = (0,3)         # n or nibble: A 4-bit value, the lowest 4 bits of the instruction
    Vx           = (8,11)       # x: A 4-bit value, the lower 4 bits of the high byte of the instruction
    Vy           = (4,7)        # y: A 4-bit value, the upper 4 bits of the low byte of the instruction
    kk          = (0,7)         # kk or byte: An 8-bit value, the lowest 8 bits of the instruction
;
```

