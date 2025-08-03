# CHIP-8 Ghidra

A (WIP) Ghidra module for reverse engineering CHIP-8 programs.

## Repository Layout

```
CHIP-8-Ghidra
├── Chip8Ghidra: The Eclipse Ghidra module project files (open using Eclipse)
│   ├── data/languages: Definition files for the CHIP-8 Ghidra processor
│   │   ├── chip8.cspec
│   │   ├── chip8.ldefs
│   │   ├── chip8.pspec
│   │   └── chip8.slaspec
│   ├── src/main/java/chip8ghidra
│   │   ├── Chip8GhidraAnalyzer.java: custom analyzer for detecting CHIP-8 sprites
│   │   └── Chip8GhidraLoader.java: custom loader for detecting and importing CHIP-8 ROMs
│   └── ghidra_scripts
│   	└── Chip8InterpretSprite.py: Jython script to manually detect CHIP-8 sprites
├── Notes
│   ├── CHIP-8 Architecture.md: notes on CHIP-8 architecture/specification
│   ├── CHIP-8 Loader Design Notes.md: design process for my custom loader
│   ├── CHIP-8 Processor Design Notes.md: design process for my custom processor
│   └── etc... (I have more notes but the above are the most relevant to the code)
└── README.md: This file
```

## Usage

Make sure to import via Ghidra's "Import Module" option; not the default "Existing Projects" option.

TODO

## Resources
Key Important Resources
- [What CHIP-8 is](https://en.m.wikipedia.org/wiki/CHIP-8)
- [CHIP-8 Specification 1](http://devernay.free.fr/hacks/chip8/C8TECH10.HTM)
- [CHIP-8 Specification 2](https://www.cs.columbia.edu/~sedwards/classes/2016/4840-spring/designs/Chip8.pdf) (nicer LaTeX PDF version)
- [Existing work that does what I want to do](https://github.com/beardypig/ghidra-chip8)
- [Ghidra Language Specification](https://ghidra.re/ghidra_docs/languages/index.html) (includes information about SLEIGH and P-Code)
- [Ghidra Processor Specification - Quick(er) Start Guide](https://github.com/joeferg425/ghidra_proc_spec)
- [About Adding an Instruction Set Architecture (ISA)](https://www.l3harris.com/newsroom/editorial/2025/01/expanding-dragon-adding-isa-ghidra)
- [Ghidra Compiler Specification](https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/compiler_spec/index.html)
Other Resources
- [Ghidra's developer guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md)
- [Example for Brainfuck](https://spinsel.dev/2020/06/17/ghidra-brainfuck-processor-1.html)
- [Example for V8 bytecode](https://swarm.ptsecurity.com/creating-a-ghidra-processor-module-in-sleigh-using-v8-bytecode-as-an-example/)
- [ghidra.re](https://ghidra.re/)

## TODO
- [x] Research CHIP-8 (take notes)
	- [x] Register layout
	- [x] Memory layout
	- [x] Instruction set
- [X] Detect CHIP-8 Instructions (Custom Ghidra Processor)
	- [x] Write LDEFS file
		- initial language definition; enables Ghidra to load your language specification (make basic declarations about the architecture of your processor)
	- [x] Write PSPEC file
		- definition for default register values and specific register names for common processor functions (such as the program counter and stack pointer)
	- [x] Write CSPEC file
		- compiler specification; define default aspects of your processor your compiler will use
	- [x] Write SLASPEC and SINC files
		- "This is where the memory, registers, opcodes, and opcode functionality are all defined"; "the meat of the processor specification"
	- [x] Use the completed Ghidra processor to examine some ROMs
- [X] Detect and Load CHIP-8 program files (Custom Ghidra Loader)
	- [X] automatically set base address to `0x200` when importing `.ch8` file
	- [X] be able to automatically load the FONTSET into the memory at `0x000` to `0x050`
- [ ] Detect CHIP-8 Sprites (Custom Ghidra Analyzer?)
	- [X] be able to detect sprites in memory (currently just looks like bytes)
	- [ ] complete automatic detection algorithm
- [ ] CHIP-8 decompilation
- [ ] Write my own game ROM and examine how it looks in Ghidra
