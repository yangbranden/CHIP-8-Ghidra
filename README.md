# CHIP-8 Ghidra Processor

## Goal
I want to make a Ghidra module/processor for reverse engineering CHIP-8 programs

## Research
Key Important Resources
- [What CHIP-8 is](https://en.m.wikipedia.org/wiki/CHIP-8)
- [CHIP-8 Specification 1](http://devernay.free.fr/hacks/chip8/C8TECH10.HTM)
- [CHIP-8 Specification 2](https://www.cs.columbia.edu/~sedwards/classes/2016/4840-spring/designs/Chip8.pdf) (nicer LaTeX PDF version)
- [Existing work that does what I want to do](https://github.com/beardypig/ghidra-chip8)
- [Ghidra Language Specification](https://ghidra.re/ghidra_docs/languages/index.html) (includes information about SLEIGH and P-Code)
- [Ghidra Processor Specification - Quick(er) Start Guide](https://github.com/joeferg425/ghidra_proc_spec)
- [About Adding an Instruction Set Architecture (ISA)](https://www.l3harris.com/newsroom/editorial/2025/01/expanding-dragon-adding-isa-ghidra)
Other Resources
- [Ghidra's developer guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md)
- [Example for Brainfuck](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-1.html)
- [Example for V8 bytecode](https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/)
- [ghidra.re](https://ghidra.re/)

## TODO
- [ ] Research CHIP-8 (take notes)
	- [ ] Register layout
	- [ ] Memory layout
	- [ ] Instruction set
- [ ] Write LDEFS file
	- [ ] initial language definition; enables Ghidra to load your language specification (make basic declarations about the architecture of your processor)
- [ ] Write PSPEC file
	- [ ] definition for default register values and specific register names for common processor functions (such as the program counter and stack pointer)
- [ ] Write OPINION file
	- [ ] specify optional logic for sub-processor families and behaviors
- [ ] Write CSPEC file
	- [ ] compiler specification; define default aspects of your processor your compiler will use
- [ ] Write SLASPEC and SINC files
	- [ ] "This is where the memory, registers, opcodes, and opcode functionality are all defined"; "the meat of the processor specification"
