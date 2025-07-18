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

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class Chip8GhidraLoader extends AbstractProgramWrapperLoader {

	// CHIP-8 programs are loaded into memory starting at 0x200
	private static final long CHIP8_PROGRAM_START_OFFSET = 0x200;
	
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
		// Get the program's memory manager
		Memory memory = program.getMemory();

		// Define the starting address for CHIP-8 programs
		Address startAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(CHIP8_PROGRAM_START_OFFSET);

		try {
			// Create a memory block starting at 0x200
			MemoryBlock block = memory.createInitializedBlock(
				"RAM",              // Block name
				startAddress,       // Starting address (0x200)
				provider.getInputStream(0), // Input stream from the file
				provider.length(),  // Size of the file
				monitor,           // Task monitor
				false              // Overlay flag
			);
			
			// Set the memory block properties
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
			
			// Add the entry point at 0x200
			program.getSymbolTable().addExternalEntryPoint(startAddress);
			
			// Optionally, create a label at the entry point
			program.getSymbolTable().createLabel(startAddress, "entry", SourceType.IMPORTED);
			
			log.appendMsg("CHIP-8 program loaded starting at address 0x200");
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
}
