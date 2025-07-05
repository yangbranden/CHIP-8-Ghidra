# Ghidra SLEIGH

SLEIGH is the language which specifies the translation from a machine instruction to [[Ghidra P-Code]]

SLEIGH is a language for describing the instruction sets of general purpose microprocessors, in order to facilitate the reverse engineering of software written for them

Used to describe microprocessors with enough detail to facilitate two major components of GHIDRA; 
- disassembly engine
- decompilation engine

A SLEIGH specification typically describes a single microprocessor and is contained in a single file

## Definition Section
### Basic Definitions
https://ghidra.re/ghidra_docs/languages/html/sleigh_definitions.html
List of things in SLEIGH specification file:
1. Endianness definition (must be the first thing defined)
2. Alignment definition
3. Space definitions (memory address spaces)
4. Registers
5. Bit range registers
- Typically used for flags
#### User-defined operations
Can define new p-code operations using a `define pcodeop` statement 

**This construction should be used sparingly**

The definition does not specify how the new operation is supposed to actually manipulate data, and any analysis routines cannot know what the specification designer intended

The operation will be treated as a black box
- If at all possible, the operation should be atomic, with specific inputs and outputs, and with no side-effects

The most common use of a new operation is to encapsulate actions that are too esoteric or too complicated to implement

## Specification Body
### Symbols
Formally, a `Specific Symbol` is defined as an identifier associated with
1. A string displayed in disassembly.
2. varnode used in semantic actions, and any p-code used to construct that varnode.

`Family Symbol`: identifier associated with a map from machine instructions to specific symbols;
```
Family Symbol: Instruction Encodings => Specific Symbols
```

The set of instruction encodings that map to a single specific symbol is called an _instruction pattern_ and is described more fully in [Section 7.4, “The Bit Pattern Section”](https://ghidra.re/ghidra_docs/languages/html/sleigh_constructors.html#sleigh_bit_pattern "7.4. The Bit Pattern Section")

#### Predefined symbols:

| **Identifier** | **Meaning**                                                          |
| -------------- | -------------------------------------------------------------------- |
| `instruction`  | The root instruction table.                                          |
| `const`        | Special address space for building constant varnodes.                |
| `unique`       | Address space for allocating temporary registers.                    |
| `inst_start`   | Offset of the address of the current instruction.                    |
| `inst_next`    | Offset of the address of the next instruction.                       |
| `inst_next2`   | Offset of the address of the instruction after the next instruction. |
| `epsilon`      | A special identifier indicating an empty bit pattern.                |

most important are `inst_start` and `inst_next`
- family symbols that map to the integer offset of either the instruction's address or the next instruction's address
- used in any relative branching situation

`inst_next2` is intended for conditional skip instruction situations

remaining symbols are rarely used; 
- `const` and `unique` identifiers are address spaces
- `epsilon` identifier is inherited from SLED and is a specific symbol equivalent to the constant `0`
-  `instruction` identifier is the root instruction table

### Tokens and Fields
`token`: byte-sized piece that makes up the machine code instructions being modeled
- use the `define token` statement
- has instruction *fields*

`field`: logical range of bits *within* an instruction that can specify an opcode, or an operand
- most basic form of family symbol

Example:
```
define token instr(16)
  opcode  = (12, 15)  # A 4-bit field for the operation code
  reg_dst = (8, 11)   # A 4-bit field for the destination register
  imm8    = (0, 7)    # An 8-bit field for an immediate value
;
```

### Attaching
`attach` keyword is used to alter either the display or semantic meaning of fields into the most common (and basic) interpretations

essentially "attaching" context to fields

#### Attaching registers
most common processor interpretation of a field is as an encoding of a particular register
```
attach variables fieldlist registerlist;
```

`fieldlist` can be a single field identifier or a space separated list of field identifiers surrounded by square brackets
- the field becomes a look-up table for the given list of registers; index into the list starting at zero
- particular integer can remain unspecified by putting a `_` character in the appropriate position

`registerlist` must be a square bracket surrounded and space separated list of register identifiers (same as in `define` statements)

#### Attaching integers
processor interprets field as an integer
```
attach values fieldlist integerlist;
```

`integerlist` is surrounded by square brackets and is a space separated list of integers

#### Attaching names
modify the display characteristics of a field without changing the semantic meaning; need for this is rare
```
attach names fieldlist stringlist;
```

`stringlist` is assigned to each of the fields in the same manner as the `attach variables` and `attach values` statements

### Context Variables
`context variable`: a `field` which is defined on top of a register rather than the instruction encoding (token)

```
define context contextreg
  fieldname=(integer,integer) attributelist
  ...
;
```

dedicated attribute `noflow`: any change is limited to a single instruction
- By default, globally setting a context variable affects instruction decoding from the point of the change

## Constructors
the unit of syntax for building new symbols; in essence, describes how to build a new family symbol

`table`: final step in creating a new `family symbol` by grouping a set of one or more constructors

constructors and tables are essentially the same; but it is only the table that has an actual family symbol identifier associated with it

### Sections of Constructor
always made up of five distinct sections in the below order:
1. Table Header
2. Display Section
3. Bit Pattern Sections
4. Disassembly Actions Section
5. Semantics Actions Section

#### 1. Table Header
each constructor starts with the identifier of the table it belongs to followed by a colon `:`

Example: definition of a constructor that is part of the table `model1`
```
mode1:           ...
```

Example: constructor in the root instruction table (added by omitting the identifier)
```
:                ...
```

The `identifier` instruction is actually reserved for root table, but should not be used in the table header; SLEIGH uses the blank identifier to distinguish ASM mnemonics from operands

#### 2. Display Section
consists of all characters after the table header `:` up to the SLEIGH keyword **is**

Characters in the display section are treated as literals with the following exceptions:
- Legal identifiers are not treated literally unless
    1. The identifier is surrounded by double quotes.
    2. The identifier is considered a mnemonic (see below).
- The character `^` has special meaning.
- White space is trimmed from the beginning and end of the section.
- Other sequences of white space characters are condensed into a single space.

Identifiers that are not treated as literals are considered to be new, initially undefined, family symbols; these are the `operands` of the constructor

Example:
```
mode1: ( op1 ),op2 is          ...
```
- constructor for table `model`
- built out of two pieces (operands); symbols `op1` and `op2`
	- these are local to the constructor; can mask global symbols with same name

##### Mnemonic
If the constructor is part of the root instruction table, the first string of characters in the display section that does not contain white space is treated as the `literal mnemonic` of the instruction and is not considered a local symbol identifier even if it is legal

Example:
```
:and (var1) is                 ...
```
- `and` is the mnemonic; it is not an operand

##### The `^` character
used to separate identifiers from other characters where there shouldn’t be white space in the disassembly display

usually used to attach display characters from a local symbol to the literal characters of the mnemonic

Example: `^` used to separate instruction mnemonic from constructor operands
```
:bra^cc op1,op2 is             ...
```

#### 3. Bit Pattern Sections
section between keyword `is` and the delimiter for the following section (either `{` or `[`)

describes a constructor's `pattern`, the subset of possible instruction encodings that the designer wants to *match* the constructor being defined

Example: assuming `opcode` was defined as a field
```
:halt is opcode=0x15 {         ...
```
- says root constructor `halt` matches any instruction where bits defining the field `opcode` have the value `0x15`

Can also use logical operators `&` or `|` and group with parentheses;
Example:
```
:nop is (opcode=0 & mode=0) | (opcode=15) { ...
```

The pattern must somehow specify all the bits and symbols being used by the constructor, even if the bits are not restricted to specific values;
Example:
```
define token instr(32)
    opcode = (0,5)
    r1 = (6,10)
    r2 = (11,15);
attach variables [ r1 r2 ] [ reg0 reg1 reg2 reg3 ];

:add r1,r2 is opcode=7 & r1 & r2 { ...
```
- `add` instruction must have bits in `opcode` field set equal to 7
- `r1` and `r2` identifiers are used (but specific values not required)

Most important operator for patterns is the concatenation operator (`;`);
Example:
```
define token base(8)
    op=(0,3)
    mode=(4,4)
    reg=(5,7);
define token immtoken(16)
    imm16 = (0,15);

:inc reg       is op=2 & reg        { ...
:add reg,imm16 is op=3 & reg; imm16 { ...
```
- `inc` uses fields `op` and `reg`; applies to a single byte (defined by `base`)
- `add` also uses `op` and `reg`, but also uses field `imm16`, defined additionally in `immtoken`

`...` operator used to satisfy token matching requirements of `&` and `|` when operands are of different length; essentially padding

#### 4. Disassembly Actions Section
optional section for doing dynamic calculations, which must be between square brackets

certain instructions need to calculate values that depend on the specific bits of the instruction, 
but which cannot be obtained as an integer interpretation of a field 
or by building with an `attach values` statement

Example: branch relocation (jump instruction)
```
jmpdest: reloc is simm8 [ reloc=inst_next + simm8*4; ] { ...
```

#### 5. Semantics Actions Section
description of how the processor would manipulate data if it actually executed an instruction that matched the constructor

surrounded by curly braces (`{ }`) and consists of zero or more statements separated by semicolons (`;`)

Most statements are built up out of C-like syntax, where the variables are the symbols visible to the constructor;

The SLEIGH compiler generates p-code operations and varnodes corresponding to the SLEIGH operators and symbols by collapsing the syntax trees represented by the statements

Example: generates exactly one integer addition operation, `INT_ADD`, where the input varnodes are `r1` and `r2` and the output varnode is `r1`
```
:add r1,r2 is opcode=0x26 & r1 & r2 { r1 = r1 + r2; }
```

`*` operator used to dereference data
Examples:
```
:load  r1,[r2] is opcode=0x99 & r1 & r2 { r1 = * r2; }
:load2 r1,[r2] is opcode=0x9a & r1 & r2 { r1 = *[other] r2; }
:load3 r1,[r2] is opcode=0x9b & r1 & r2 { r1 = *:2 r2; }
:load4 r1,[r2] is opcode=0x9c & r1 & r2 { r1 = *[other]:2 r2; }
```

## P-code Macros
allows the designer to define p-code subroutines which can be invoked as part of a constructor’s semantic action

Example:
```
macro resultflags(op) {
  zeroflag = (op == 0);
  signflag = (op1 s< 0);
}

:add r1,r2 is opcode=0xba & r1 & r2 { r1 = r1 + r2; resultflags(r1); }
```


