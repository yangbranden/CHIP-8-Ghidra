# Ghidra P-Code

Referenced: [P-Code Reference Manual](https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcoderef.html)

"_register transfer language_" designed for reverse engineering applications

Essentially a generalized language for modeling behavior of many different processors

P-code works by translating individual processor instructions into a sequence of `p-code operations` that take parts of the processor state as input and output variables (`varnodes`)

P-code has a set of unique operations; it has **opcodes**
- Direct translation into these operations is called "raw p-code"

P-code is designed specifically to facilitate _data-flow_ graphs;
- `varnodes` and `p-code operators` can be thought of as nodes in these graphs
- Opcodes `MULTIEQUAL` and `INDIRECT` are specific to the graph construction process
- Opcodes `CALL`, `CALLIND`, and `RETURN`, may have their input and output varnodes changed during analysis so that they no longer match their _raw p-code_ form

Core concepts of p-code:
- Address space
- Varnode
- P-code Operation

## Address Space
Generalization of RAM

Each byte has an `address`

Any data that a processor manipulates must be in some address space

Address spaces have:
- a name
- a size (number of unique indices/addresses)
- and an `endianness`

A typical processor will have:
- a `ram` space: to model memory accessible via main data bus
- a `register` space: for modeling general purpose registers 
- free to define as many address spaces as it needs

Special address space called the `constant` address space used to encode any constant values needed for p-code operations

Generally also exists a dedicated `temporary` space, which can be viewed as a bottomless source of temporary registers

#### `wordsize` attribute
Each address space has a `wordsize` attribute that can be set to indicate the number of bytes in a unit; `wordsize` > 1 makes little difference to the representation of p-code

All the offsets into an address space are still represented internally as a byte offset;
- except for `LOAD` and `STORE` p-code operations; 
- These operations read a pointer offset that must be scaled properly to get the right byte offset when dereferencing the pointer

## Varnode
Generalization of either a register or a memory location

Represented by the formal triple: 
- an address space, 
- an offset into the space, and 
- a size

Intuitively, simply a contiguous sequence of bytes that can be treated as a single value

Varnodes have no type; but p-code operations can force one of three _type_ interpretations:
- **Integer**: Operations that manipulate integers always interpret a varnode as a twos-complement encoding using the endianess associated with the address space containing the varnode.
- **Boolean**: A varnode being used as a boolean value is assumed to be a single byte that can only take the value 0, for _false_, and 1, for _true_.
- **Floating-point**: Floating-point operations use the encoding expected by the processor being modeled, which varies depending on the size of the varnode. For most processors, these encodings are described by the IEEE 754 standard, but other encodings are possible in principle.

If a varnode is specified as an offset into the `constant` address space, that offset is interpreted as a constant, or immediate value, in any p-code operation that uses that varnode

## P-code Operation
A **p-code operation** is the analog of a machine instruction

All p-code operations have the same basic format internally; take one or more varnodes as input, optionally produce a single output varnode

Action determined by `opcode`
- In general, the size or precision of a particular p-code operation is determined by the size of the varnode inputs or output, not by the opcode

All p-code operations are associated with the address of the original processor instruction they were translated from; 
- For a single instruction, a 1-up counter, starting at zero, is used to enumerate the multiple p-code operations involved in its translation
- The address and counter as a pair are referred to as the p-code op's unique `sequence number`
- Control-flow of p-code operations generally follows sequence number order

Also see: [Pseudo P-Code Operations](https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pseudo-ops.html)
