# CHIP-8 Ghidra Processor

A (WIP) Ghidra module/processor for reverse engineering CHIP-8 programs.

## Repository Layout

```
CHIP-8-Ghidra-Processor
├── Chip8_Processor: The Eclipse Ghidra module project files (open using Eclipse)
│   ├── data: Definition files for the CHIP-8 Ghidra processor
│   │   ├── languages
│   │   │   ├── chip8.cspec
│   │   │   ├── chip8.ldefs
│   │   │   ├── chip8.opinion
│   │   │   ├── chip8.pspec
│   │   │   ├── chip8.sinc
│   │   │   ├── chip8.slaspec
│   │   │   └── TBD
│   ├── src: some stuff idk about yet
│   │   └── TBD
│   └── TBD
├── Notes
│   └── Architecture.md: notes on CHIP-8 architecture/specification
└── README.md: This file
```

## Resources
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
- [X] Research CHIP-8 (take notes)
	- [X] Register layout
	- [X] Memory layout
	- [X] Instruction set
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

## Schedule

Target Completion Date: 7/25/2025

| Task                                                                                                                                   | Target Completion Date | Notes                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Notes on CHIP-8; <br>- Register layout<br>- Memory layout<br>- Instruction set                                                         | 6/27                   | Should know everything necessary about the langauge to define a Ghidra processor                                                                     |
| Complete development of Ghidra processor<br>- LDEFS file<br>- PSPEC file<br>- OPINION file<br>- CSPEC file<br>- SLASPEC and SINC files | 7/4                    | Will maybe not be perfect, but should be usable by this milestone                                                                                    |
| Use the completed Ghidra processor to examine some ROMs; take notes on observations                                                    | 7/11                   | I want to have some sort of meaningful results or understanding gained from looking at the disassembled game ROMs; i.e. be able to write my own game |
| Write my own game ROM and examine how it looks in Ghidra                                                                               | 7/18                   | maybe snake? tetris? idk                                                                                                                             |
| Prepare technical presentation on work done, lessons learned, etc.                                                                     | 7/25                   |                                                                                                                                                      |