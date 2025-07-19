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

import java.util.*;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * CHIP-8 Sprite Analyzer - Detects and annotates sprite data in CHIP-8 programs
 * by finding the best-fit size for each potential sprite.
 */
public class Chip8GhidraAnalyzer extends AbstractAnalyzer {

    private Set<Long> candidateSpriteAddresses;
    private Set<Integer> candidateSpriteLengths;
    private Map<Long, Integer> bestFitSprites;

    public Chip8GhidraAnalyzer() {
        super("CHIP-8 Sprite Analyzer", "Analyzes CHIP-8 code to find and define sprites.", AnalyzerType.BYTE_ANALYZER);
        candidateSpriteAddresses = new HashSet<>();
        candidateSpriteLengths = new HashSet<>();
        bestFitSprites = new HashMap<>();
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }

    @Override
    public void registerOptions(Options options, Program program) {
        // No custom options needed for this analyzer
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        System.out.println("Starting CHIP-8 Sprite Detection...");

        // Step 1: Find all candidate sprite addresses and lengths from instructions.
        findCandidates(program, monitor, log);
        System.out.println(String.format("Found %d candidate addresses and %d candidate lengths.",
            candidateSpriteAddresses.size(), candidateSpriteLengths.size()));

        // Step 2: For each candidate address, determine the best-fit sprite length.
        determineBestFitSprites(program, log);
        System.out.println(String.format("Determined %d best-fit sprites.", bestFitSprites.size()));

        // Step 3: Create Ghidra data structures for the identified best-fit sprites.
        createGhidraStructuresForBestFit(program, log);

        System.out.println("Sprite detection complete.");
        return true;
    }

    /**
     * Scans the program for LD I, addr and DRW instructions to populate candidate lists.
     */
    private void findCandidates(Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        candidateSpriteAddresses.clear();
        candidateSpriteLengths.clear();

        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(true);

        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instrIter.next();
            if (isLoadIInstruction(instruction)) {
                Long addrValue = getLoadIAddress(instruction);
                if (addrValue != null) {
                    candidateSpriteAddresses.add(addrValue);
                }
            } else if (isDrwInstruction(instruction)) {
                int spriteHeight = getSpriteHeight(instruction);
                if (spriteHeight > 0) {
                    candidateSpriteLengths.add(spriteHeight);
                }
            }
        }
    }

    /**
     * Iterates through candidate addresses and lengths to find the optimal length for each address.
     * The best fit is the one with the fewest null bytes.
     */
    private void determineBestFitSprites(Program program, MessageLog log) {
        bestFitSprites.clear();

        // For each potential sprite location...
        for (Long address : candidateSpriteAddresses) {
            int bestLength = -1;
            int minNullBytes = Integer.MAX_VALUE;

            // ...go through each posisble sprite length and try to find the most accurate size for the sprite
            // based on the number of null bytes present in memory region
            for (Integer length : candidateSpriteLengths) {
                if (!isValidPotentialSprite(program, address, length)) {
                    continue;
                }

                List<Integer> spriteData = readSpriteData(program, address, length);
                if (spriteData == null || spriteData.size() != length) {
                    continue;
                }

                int nullByteCount = countNullBytes(spriteData);

                // Sprites should not be made entirely of null bytes
                if (nullByteCount == length) {
                    continue;
                }

                // Lower null byte count == better potential fit
                if (nullByteCount < minNullBytes) {
                    minNullBytes = nullByteCount;
                    bestLength = length;
                }
            }

            if (bestLength != -1) {
                bestFitSprites.put(address, bestLength);
            }
        }
    }
    
    /**
     * Creates Ghidra data types, labels, and comments for the final best-fit sprites.
     */
    private void createGhidraStructuresForBestFit(Program program, MessageLog log) {
        List<Long> sortedAddresses = new ArrayList<>(bestFitSprites.keySet());
        Collections.sort(sortedAddresses);

        for (Long address : sortedAddresses) {
            int height = bestFitSprites.get(address);
            try {
                Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
                
                List<Integer> spriteData = readSpriteData(program, address, height);
                if (spriteData == null) continue;
                
                createGhidraDataStructure(program, startAddr, height);
                addSpriteComments(program, startAddr, spriteData, address);
                System.out.println(String.format("Created sprite at 0x%03X, height %d", address, height));
                
            } catch (Exception e) {
                System.out.println(String.format("Error creating sprite at 0x%03X: %s", address, e.getMessage()));
            }
        }
    }

    // ======== Helper and Utility Methods ========

    private int countNullBytes(List<Integer> data) {
        return (int) data.stream().filter(b -> b == 0).count();
    }
    
    private boolean isValidPotentialSprite(Program program, long address, int height) {
        long endOffset = address + height;
        final long VALID_REGION_END = 4096; // CHIP-8 memory size
        if (address < 0 || endOffset > VALID_REGION_END) {
            return false;
        }

        Listing listing = program.getListing();
        try {
            Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            for (int i = 0; i < height; i++) {
                // Region overlaps with existing code
                if (listing.getInstructionAt(startAddr.add(i)) != null) {
                    return false;
                }
            }
        } catch (AddressOutOfBoundsException e) {
            return false;
        }
        return true;
    }
    
    private boolean isDrwInstruction(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            return bytes.length >= 2 && (bytes[0] & 0xF0) == 0xD0;
        } catch (Exception e) {
            return false;
        }
    }

    private int getSpriteHeight(Instruction drwInstruction) {
        try {
            byte[] bytes = drwInstruction.getBytes();
            return bytes.length >= 2 ? (bytes[1] & 0x0F) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private boolean isLoadIInstruction(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            return bytes.length >= 2 && (bytes[0] & 0xF0) == 0xA0;
        } catch (Exception e) {
            return false;
        }
    }

    private Long getLoadIAddress(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                return (long) (((bytes[0] & 0x0F) << 8) | (bytes[1] & 0xFF));
            }
        } catch (Exception e) {
            continue;
        }
        return null;
    }

    private List<Integer> readSpriteData(Program program, long address, int height) {
        List<Integer> spriteData = new ArrayList<>();
        Memory memory = program.getMemory();
        try {
            Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            for (int i = 0; i < height; i++) {
                byte byteVal = memory.getByte(startAddr.add(i));
                spriteData.add(byteVal & 0xFF);
            }
            return spriteData;
        } catch (Exception e) {
            return null;
        }
    }

    private void createGhidraDataStructure(Program program, Address addrObj, int height) throws Exception {
        DataTypeManager dataManager = program.getDataTypeManager();
        Listing listing = program.getListing();
        DataType byteType = dataManager.getDataType("/byte");
        if (byteType == null) {
            byteType = new ByteDataType();
        }

        listing.clearCodeUnits(addrObj, addrObj.add(height - 1), false);
        for (int i = 0; i < height; i++) {
            listing.createData(addrObj.add(i), byteType);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        String spriteName = String.format("SPRITE_0x%03X", addrObj.getOffset());
        symbolTable.createLabel(addrObj, spriteName, SourceType.ANALYSIS);
    }
    
    private void addSpriteComments(Program program, Address startAddr, List<Integer> spriteData, long baseAddress) {
        Listing listing = program.getListing();
        String headerComment = String.format("Sprite 0x%03X (%dx8)", baseAddress, spriteData.size());
        listing.setComment(startAddr, CodeUnit.PRE_COMMENT, headerComment);

        for (int i = 0; i < spriteData.size(); i++) {
            try {
                Address rowAddr = startAddr.add(i);
                int byteVal = spriteData.get(i);
                StringBuilder visualRow = new StringBuilder();
                for (int bit = 7; bit >= 0; bit--) {
                    visualRow.append(((byteVal >> bit) & 1) != 0 ? "#" : ".");
                }
                String comment = String.format("0x%02X |%s|", byteVal, visualRow.toString());
                listing.setComment(rowAddr, CodeUnit.EOL_COMMENT, comment);
            } catch (Exception e) {
                continue;
            }
        }
    }
}