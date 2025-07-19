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
 */
public class Chip8GhidraAnalyzer extends AbstractAnalyzer {
    
    private List<Instruction> drwInstructions;
    private Map<String, SpriteInfo> potentialSpriteAddresses;
    private Set<Long> analyzedAddresses;
    
    public Chip8GhidraAnalyzer() {
        super("CHIP-8 Sprite Analyzer", "Analyzer to detect CHIP-8 sprites", AnalyzerType.BYTE_ANALYZER);
        drwInstructions = new ArrayList<>();
        potentialSpriteAddresses = new HashMap<>();
        analyzedAddresses = new HashSet<>();
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
        
        // Step 1: Find all DRW instructions
        findDrwInstructions(program, monitor, log);
        System.out.println("DRW instructions found: " + drwInstructions.size());
        
        // Step 2: Analyze possible I register values for each DRW
        getPotentialSpriteAddresses(program, log);
        
        // Step 3: Create sprite data structures
        createSpriteDataStructures(program, log);
        
        System.out.println("Sprite detection complete.");
        return true;
    }
    
    private void findDrwInstructions(Program program, TaskMonitor monitor, MessageLog log) 
            throws CancelledException {
        
        drwInstructions.clear();
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(true);
        
        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instrIter.next();
            if (isDrwInstruction(instruction)) {
                drwInstructions.add(instruction);
                System.out.println("Found DRW at: " + instruction.getAddress());
            }
        }
    }
    
    private boolean isDrwInstruction(Instruction instruction) {
        if (instruction == null) return false;
        
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                int firstByte = bytes[0] & 0xFF;
                return (firstByte & 0xF0) == 0xD0;
            }
        } catch (Exception e) {
            // Ignore exceptions
        }
        return false;
    }
    
    private void getPotentialSpriteAddresses(Program program, MessageLog log) {
        potentialSpriteAddresses.clear();
        
        for (Instruction drwInstruction : drwInstructions) {
            System.out.println("Analyzing DRW at: " + drwInstruction.getAddress());
            
            int spriteHeight = getSpriteHeight(drwInstruction);
            Set<Long> iValues = findIRegisterValues(program, log);
            
            String drwAddr = drwInstruction.getAddress().toString();
            potentialSpriteAddresses.put(drwAddr, new SpriteInfo(spriteHeight, iValues));
        }
    }
    
    private int getSpriteHeight(Instruction drwInstruction) {
        try {
            byte[] bytes = drwInstruction.getBytes();
            if (bytes.length >= 2) {
                return bytes[1] & 0x0F; // Height is the last nibble (n in Dxyn)
            }
        } catch (Exception e) {
            // Ignore exceptions
        }
        return 1;
    }
    
    private Set<Long> findIRegisterValues(Program program, MessageLog log) {
        Set<Long> iAddresses = new HashSet<>();
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(true);
        
        while (instrIter.hasNext()) {
            Instruction instruction = instrIter.next();
            if (isLoadIInstruction(instruction)) {
                Long addrValue = getLoadIAddress(instruction);
                if (addrValue != null) {
                    iAddresses.add(addrValue);
                    System.out.println(String.format("  Found LD I, 0x%03X at %s", 
                        addrValue, instruction.getAddress()));
                }
            }
        }
        return iAddresses;
    }
    
    private boolean isLoadIInstruction(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                int firstByte = bytes[0] & 0xFF;
                return (firstByte & 0xF0) == 0xA0; // A in first nibble
            }
        } catch (Exception e) {
            // Ignore exceptions
        }
        return false;
    }
    
    private Long getLoadIAddress(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                // Address is the last 12 bits (nnn in Annn)
                long addr = ((bytes[0] & 0x0F) << 8) | (bytes[1] & 0xFF);
                return addr;
            }
        } catch (Exception e) {
            // Ignore exceptions
        }
        return null;
    }
    
    private void createSpriteDataStructures(Program program, MessageLog log) {
        for (Map.Entry<String, SpriteInfo> entry : potentialSpriteAddresses.entrySet()) {
            SpriteInfo info = entry.getValue();
            int spriteHeight = info.getSpriteHeight();
            Set<Long> possibleAddresses = info.getPossibleIValues();
            
            for (Long spriteAddr : possibleAddresses) {
                if (!analyzedAddresses.contains(spriteAddr)) {
                    analyzeAndCreateSprite(program, spriteAddr, spriteHeight, log);
                }
            }
        }
    }
    
    private void analyzeAndCreateSprite(Program program, long address, int height, MessageLog log) {
        analyzedAddresses.add(address);
        
        try {
            Address addrObj = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            List<Integer> spriteData = readSpriteData(program, addrObj, height);
            
            if (spriteData != null && isValidSpriteData(program, spriteData, addrObj, height, log)) {
                createGhidraDataStructure(program, addrObj, height);
                addSpriteComments(program, addrObj, spriteData, address);
                System.out.println(String.format("Created sprite at 0x%03X, height %d", address, height));
            }
        } catch (Exception e) {
            System.out.println(String.format("Error creating sprite at 0x%03X: %s", address, e.getMessage()));
        }
    }
    
    private List<Integer> readSpriteData(Program program, Address addrObj, int height) {
        List<Integer> spriteData = new ArrayList<>();
        Memory memory = program.getMemory();
        
        for (int i = 0; i < height; i++) {
            try {
                byte byteVal = memory.getByte(addrObj.add(i));
                spriteData.add(byteVal & 0xFF);
            } catch (Exception e) {
                return null; // Can't read memory
            }
        }
        return spriteData;
    }
    
    private boolean isValidSpriteData(Program program, List<Integer> spriteData, Address addrObj, 
            int height, MessageLog log) {
        if (spriteData == null || spriteData.isEmpty()) {
            return false;
        }
        
        // Check if region is all zeros (no sprite data)
        if (spriteData.stream().allMatch(b -> b == 0)) {
            return false;
        }
        
        // Check if any of the sprite bytes are already instructions
        Listing listing = program.getListing();
        for (int i = 0; i < height; i++) {
            Address checkAddr = addrObj.add(i);
            Instruction existingInstruction = listing.getInstructionAt(checkAddr);
            if (existingInstruction != null) {
                System.out.println(String.format("Skipping sprite at 0x%03X - contains instruction at 0x%03X",
                    addrObj.getOffset(), checkAddr.getOffset()));
                return false;
            }
        }
        return true;
    }
    
    private void createGhidraDataStructure(Program program, Address addrObj, int height) 
            throws Exception {
        DataTypeManager dataManager = program.getDataTypeManager();
        Listing listing = program.getListing();
        
        DataType byteType;
        try {
            byteType = dataManager.getDataType("/byte");
            if (byteType == null) {
                byteType = new ByteDataType();
            }
        } catch (Exception e) {
            byteType = new ByteDataType();
        }
        
        // Clear any existing data
        listing.clearCodeUnits(addrObj, addrObj.add(height - 1), false);
        
        // Create individual byte data structures
        for (int i = 0; i < height; i++) {
            Address byteAddr = addrObj.add(i);
            listing.createData(byteAddr, byteType);
        }
        
        // Create a label for the sprite
        SymbolTable symbolTable = program.getSymbolTable();
        String spriteName = String.format("SPRITE_0x%03X", addrObj.getOffset());
        symbolTable.createLabel(addrObj, spriteName, SourceType.USER_DEFINED);
    }
    
    private void addSpriteComments(Program program, Address startAddr, List<Integer> spriteData, 
            long baseAddress) {
        Listing listing = program.getListing();
        
        // Add header comment for the sprite
        String headerComment = String.format("Sprite 0x%03X (%dx8):", baseAddress, spriteData.size());
        try {
            listing.setComment(startAddr, CodeUnit.PRE_COMMENT, headerComment);
        } catch (Exception e) {
            // Ignore comment errors
        }
        
        // Add individual row comments
        for (int i = 0; i < spriteData.size(); i++) {
            try {
                Address rowAddr = startAddr.add(i);
                int byteVal = spriteData.get(i);
                
                // Create visual representation
                StringBuilder visualRow = new StringBuilder();
                for (int bit = 0; bit < 8; bit++) {
                    if ((byteVal & (0b10000000 >> bit)) != 0) {
                        visualRow.append("#"); // Filled pixel
                    } else {
                        visualRow.append("."); // Empty pixel
                    }
                }
                
                String comment = String.format("0x%02X |%s| Row %d", byteVal, visualRow.toString(), i);
                listing.setComment(rowAddr, CodeUnit.EOL_COMMENT, comment);
            } catch (Exception e) {
                // Ignore comment errors
            }
        }
    }
    
    // Helper class to store sprite information
    private static class SpriteInfo {
        private final int spriteHeight;
        private final Set<Long> possibleIValues;
        
        public SpriteInfo(int spriteHeight, Set<Long> possibleIValues) {
            this.spriteHeight = spriteHeight;
            this.possibleIValues = possibleIValues;
        }
        
        public int getSpriteHeight() {
            return spriteHeight;
        }
        
        public Set<Long> getPossibleIValues() {
            return possibleIValues;
        }
    }
}
