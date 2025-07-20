(contents of my presentation)
# Abstract
CHIP-8, developed in the mid-1970s, is an interpreted programming language that enabled simple game development on early microcomputers. Today, it serves as a "Hello World" exercise for emulation development, acting as a rite of passage for aspiring developers. Despite its age and simplicity, CHIP-8 remains relevant as an educational platform for understanding core concepts in emulation and computer architecture. 

This presentation details my development of a CHIP-8 emulator alongside a comprehensive Ghidra module, providing both execution and analysis capabilities for CHIP-8 programs. It covers the key technical challenges, from implementing the instruction set and handling memory operations to creating a custom Ghidra toolkit that includes a processor definition, loader, and analyzer. This talk documents my development journey with CHIP-8, highlighting the key problems solved and insights gained along the way.

## whoami
me (skipping this slide for these notes)

## What is CHIP-8?
- Interpreted programming language
- Joseph Weisbecker, engineer at RCA
- Used on 8-bit microcomputers in 1970s
- Today, used as “Hello World” of emulation dev

![[CHIP8Pong.png|400]]

![[CHIP8Telmac1800.png|400]]

COSMAC VIP
![[COSMACVIP.png|400]]

Telmac 1800
![[Telmac1800.png|400]]

- Today, used as "Hello World" of emulation development
- CHIP-8 “emulator” is really a language interpreter

![[AwesomeCHIP8Description.png]]
[https://chip-8.github.io/links/](https://chip-8.github.io/links/)

![[EmuDevReddit.png]]
[https://www.reddit.com/r/EmuDev](https://www.reddit.com/r/EmuDev/comments/6lgzzd/what_is_chip8_and_why_does_everyone_want_to/)

# Creating a CHIP-8 Emulator
## CHIP-8 Architecture
- 4 KB (4096 bytes) of memory
	- 12-bit addresses (2 bytes)
- Registers
	- 16 8-bit general purpose (V0-VF) 
	- 16-bit “index” register (I)
	- 16-bit program counter (PC)
	- 8-bit stack pointer (SP)
	- 8-bit delay timer (DT)
	- 8-bit sound timer (ST)
- 16-slot stack for return addresses

![[CHIP8MemoryLayout.png]]
[CHIP-8 Memory Layout](https://www.cs.columbia.edu/~sedwards/classes/2016/4840-spring/designs/Chip8.pdf)

- 64x32 pixel display
- 16-key input pad
- Single tone buzzer

![[CHIP8Hardware.png|400]]

![[CHIP8Keypad.png|400]]
[CHIP-8 Keypad](http://devernay.free.fr/hacks/chip8/C8TECH10.HTM#2.3)

![[CHIP8Display.png|500]]
[CHIP-8 Display](http://devernay.free.fr/hacks/chip8/C8TECH10.HTM#2.4)

## CHIP-8 Architecture Overview
![[CHIP8ArchitectureOverview.png]]
[https://www.cs.columbia.edu/~sedwards/classes/2016/4840-spring/designs/Chip8.pdf](https://www.cs.columbia.edu/~sedwards/classes/2016/4840-spring/designs/Chip8.pdf)

## CHIP-8 Architecture (Code)
- Rust "class" (`struct` & `impl`)

![[Chip8EmuStruct.png]]
struct

![[CHIP8EmuImpl.png]]
impl

