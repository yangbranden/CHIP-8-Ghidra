/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package chip8ghidra;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CommentType;
import java.io.ByteArrayInputStream;


/**
 * Provide class-level documentation that describes what this loader does.
 */
public class Chip8GhidraLoader extends AbstractProgramWrapperLoader {

	// CHIP-8 programs are loaded into memory starting at 0x200
	private static final long CHIP8_PROGRAM_START_OFFSET = 0x200;

	// CHIP-8 Default Font Set
	private static final byte[] CHIP8_FONTSET = {
		(byte)0xF0, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0xF0, // 0
		(byte)0x20, (byte)0x60, (byte)0x20, (byte)0x20, (byte)0x70, // 1
		(byte)0xF0, (byte)0x10, (byte)0xF0, (byte)0x80, (byte)0xF0, // 2
		(byte)0xF0, (byte)0x10, (byte)0xF0, (byte)0x10, (byte)0xF0, // 3
		(byte)0x90, (byte)0x90, (byte)0xF0, (byte)0x10, (byte)0x10, // 4
		(byte)0xF0, (byte)0x80, (byte)0xF0, (byte)0x10, (byte)0xF0, // 5
		(byte)0xF0, (byte)0x80, (byte)0xF0, (byte)0x90, (byte)0xF0, // 6
		(byte)0xF0, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x40, // 7
		(byte)0xF0, (byte)0x90, (byte)0xF0, (byte)0x90, (byte)0xF0, // 8
		(byte)0xF0, (byte)0x90, (byte)0xF0, (byte)0x10, (byte)0xF0, // 9
		(byte)0xF0, (byte)0x90, (byte)0xF0, (byte)0x90, (byte)0x90, // A
		(byte)0xE0, (byte)0x90, (byte)0xE0, (byte)0x90, (byte)0xE0, // B
		(byte)0xF0, (byte)0x80, (byte)0x80, (byte)0x80, (byte)0xF0, // C
		(byte)0xE0, (byte)0x90, (byte)0x90, (byte)0x90, (byte)0xE0, // D
		(byte)0xF0, (byte)0x80, (byte)0xF0, (byte)0x80, (byte)0xF0, // E
		(byte)0xF0, (byte)0x80, (byte)0xF0, (byte)0x80, (byte)0x80  // F
	};
	
	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion files.

		return "CHIP-8 Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Assume we are loading a CHIP-8 program if the provider is not empty.
		// In a more complex architecture, we would likely want to check the file type or contents.
		if (provider.length() > 0) {
			loadSpecs.add(new LoadSpec(this, CHIP8_PROGRAM_START_OFFSET, true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		try {
			// Get the program's memory manager
			Memory memory = program.getMemory();


			// ========== Memory Block for CHIP-8 FONTSET ==========
			// Define the starting address for the CHIP-8 font set as an Address object (at 0x000)
			Address fontsetStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x000);

			// Create a memory block for the CHIP-8 font set
			MemoryBlock fontsetBlock = memory.createInitializedBlock(
				"CHIP8_FONTSET",
				fontsetStart,
				new ByteArrayInputStream(CHIP8_FONTSET),
				CHIP8_FONTSET.length,
				monitor,
				false
			);

			// Set properties for the fontset memory block
			fontsetBlock.setRead(true);
			fontsetBlock.setWrite(false);
			fontsetBlock.setExecute(false);

			// Create labels and EOL comments for each character in the font set
			for (int i = 0; i < CHIP8_FONTSET.length / 5; i++) {
				Address charAddress = fontsetStart.add(i * 5);
				String charLabel = String.format("FONTSET_%X", i);
				program.getSymbolTable().createLabel(charAddress, charLabel, SourceType.IMPORTED);
				addFontSpriteComments(program, charAddress, i);
			}

			log.appendMsg("CHIP-8 font set loaded at: 0x000");


			// ========== Memory Block for Loading CHIP-8 ROM ==========
			// Define the starting address for CHIP-8 programs as an Address object (at 0x200)
			Address programStart = program.getAddressFactory().getDefaultAddressSpace().getAddress(CHIP8_PROGRAM_START_OFFSET);

			// Create a memory block starting for the CHIP-8 program ROM
			MemoryBlock block = memory.createInitializedBlock(
				"CHIP8_ROM",              	// Block name
				programStart,              	// Starting address (0x200)
				provider.getInputStream(0), // Input stream from the file
				provider.length(),  		// Size of the file
				monitor,           			// Task monitor
				false              			// Overlay flag
			);
			
			// Set program memory block properties
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
			
			// Add the entry point at 0x200
			program.getSymbolTable().addExternalEntryPoint(programStart);
			
			// Create a label at the entry point
			program.getSymbolTable().createLabel(programStart, "main", SourceType.IMPORTED);
			
			log.appendMsg("CHIP-8 program loaded starting at: 0x200");
		} catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to load CHIP-8 program", e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}

	private void addFontSpriteComments(Program program, Address startAddr, int fontChar) {
		Listing listing = program.getListing();
		MemoryBlock memory = program.getMemory().getBlock(startAddr);
		
		if (memory == null) return;
		
		// Add a header comment for the font character
		String headerComment = String.format("Font set character 0x%X (5x8):", fontChar);
		try {
			listing.setComment(startAddr, CommentType.PRE, headerComment);
		} catch (Exception e) {
			// Ignore comment setting errors
		}
		
		// Add individual row comments for each of the 5 bytes
		for (int i = 0; i < 5; i++) {
			try {
				Address rowAddr = startAddr.add(i);
				
				// Read the byte from memory
				byte spriteByte = memory.getByte(rowAddr);
				int byteVal = spriteByte & 0xFF;
				
				// Create visual representation using ASCII characters
				StringBuilder visualRow = new StringBuilder();
				for (int bit = 0; bit < 8; bit++) {
					if ((byteVal & (0x80 >> bit)) != 0) {
						visualRow.append("#");  // Filled pixel
					} else {
						visualRow.append(".");  // Empty pixel
					}
				}
				
				// Create the comment with hex value and visualization
				String comment = String.format("0x%02X |%s| Row %d", byteVal, visualRow.toString(), i);
				
				// Add as end-of-line comment
				listing.setComment(rowAddr, CommentType.EOL, comment);
				
			} catch (Exception e) {
				System.out.println(String.format("Error adding comment at font char %d, row %d: %s", 
					fontChar, i, e.getMessage()));
			}
		}
	}
}
