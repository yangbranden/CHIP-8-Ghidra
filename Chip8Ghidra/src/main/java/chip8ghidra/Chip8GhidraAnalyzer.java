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
 * by associating I register modifications with their closest DRW instructions.
 */
public class Chip8GhidraAnalyzer extends AbstractAnalyzer {

    // Data classes for tracking instructions and associations
    private static class IModification {
        long instructionAddr;
        String instructionType;
        long iValue;
        
        IModification(long addr, String type, long value) {
            this.instructionAddr = addr;
            this.instructionType = type;
            this.iValue = value;
        }
    }
    
    private static class DrwInstruction {
        long drwAddr;
        int spriteHeight;
        
        DrwInstruction(long addr, int height) {
            this.drwAddr = addr;
            this.spriteHeight = height;
        }
    }
    
    private static class SpriteAssociation {
        long iAddr;
        long iValue;
        long drwAddr;
        int spriteHeight;
        
        SpriteAssociation(long iAddr, long iValue, long drwAddr, int spriteHeight) {
            this.iAddr = iAddr;
            this.iValue = iValue;
            this.drwAddr = drwAddr;
            this.spriteHeight = spriteHeight;
        }
    }

    private List<IModification> iModifications;
    private List<DrwInstruction> drwInstructions;
    private List<SpriteAssociation> spriteAssociations;

    public Chip8GhidraAnalyzer() {
        super("CHIP-8 Sprite Analyzer", "Analyzes CHIP-8 code to find and define sprites with I-to-DRW association.", AnalyzerType.BYTE_ANALYZER);
        iModifications = new ArrayList<>();
        drwInstructions = new ArrayList<>();
        spriteAssociations = new ArrayList<>();
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
        // No custom options needed
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        System.out.println("Starting CHIP-8 Sprite Detection with I-to-DRW association...");

        // Step 1: Find all instructions that modify I register
        findIModifications(program, monitor);
        System.out.println(String.format("Found %d I modification instructions.", iModifications.size()));

        // Step 2: Find all DRW instructions
        findDrwInstructions(program, monitor);
        System.out.println(String.format("Found %d DRW instructions.", drwInstructions.size()));

        // Step 3: Associate each I modification with closest DRW
        associateIWithClosestDrw();
        System.out.println(String.format("Created %d I-to-DRW associations.", spriteAssociations.size()));

        // Step 4: Create sprites based on associations
        createSpritesFromAssociations(program, log);

        System.out.println("Sprite detection complete.");
        return true;
    }

    /**
     * Find all LD I and ADD I instructions that modify the I register.
     */
    private void findIModifications(Program program, TaskMonitor monitor) throws CancelledException {
        iModifications.clear();
        
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(true);

        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instrIter.next();
            long addr = instruction.getAddress().getOffset();
            
            if (isLoadIInstruction(instruction)) {
                Long iValue = getLoadIAddress(instruction);
                if (iValue != null) {
                    iModifications.add(new IModification(addr, "LD_I", iValue));
                }
            } else if (isAddIInstruction(instruction)) {
                // For ADD I, Vx - calculate the resulting I value
                Integer vxReg = getAddIRegister(instruction);
                if (vxReg != null) {
                    Long iValue = calculateAddIResult(program, addr, vxReg);
                    if (iValue != null) {
                        iModifications.add(new IModification(addr, "ADD_I", iValue));
                    }
                }
            }
        }
    }

    /**
     * Find all DRW instructions.
     */
    private void findDrwInstructions(Program program, TaskMonitor monitor) throws CancelledException {
        drwInstructions.clear();
        
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(true);

        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instrIter.next();
            if (isDrwInstruction(instruction)) {
                long addr = instruction.getAddress().getOffset();
                int spriteHeight = getSpriteHeight(instruction);
                if (spriteHeight > 0) {
                    drwInstructions.add(new DrwInstruction(addr, spriteHeight));
                }
            }
        }
    }

    /**
     * Associate each I modification with its closest DRW instruction.
     */
    private void associateIWithClosestDrw() {
        spriteAssociations.clear();
        
        for (IModification iMod : iModifications) {
            // Find the DRW instruction with minimal address distance
            DrwInstruction closestDrw = null;
            long minDistance = Long.MAX_VALUE;
            
            for (DrwInstruction drw : drwInstructions) {
                long distance = Math.abs(drw.drwAddr - iMod.instructionAddr);
                if (distance < minDistance) {
                    minDistance = distance;
                    closestDrw = drw;
                }
            }
            
            if (closestDrw != null) {
                spriteAssociations.add(new SpriteAssociation(
                    iMod.instructionAddr, iMod.iValue, closestDrw.drwAddr, closestDrw.spriteHeight));
                System.out.println(String.format(
                    "I modification at 0x%03X (I=0x%03X) -> DRW at 0x%03X (height=%d)",
                    iMod.instructionAddr, iMod.iValue, closestDrw.drwAddr, closestDrw.spriteHeight));
            }
        }
    }

    /**
     * Calculate the resulting I value from ADD I, Vx instruction.
     */
    private Long calculateAddIResult(Program program, long addIAddr, int vxRegister) {
        // First, find the preceding LD I instruction to get base I value
        Long baseIValue = findPrecedingLdI(addIAddr);
        if (baseIValue == null) {
            return null;
        }
        
        // Find the value in Vx register
        int vxValue = findPrecedingVxValue(program, addIAddr, vxRegister);
        
        long resultIValue = baseIValue + vxValue;
        
        // Validate that result points to potential sprite data (not instructions)
        if (isValidSpriteLocation(program, resultIValue)) {
            return resultIValue;
        }
        
        return null;
    }

    /**
     * Find the most recent LD I instruction before current address.
     */
    private Long findPrecedingLdI(long currentAddr) {
        for (int i = iModifications.size() - 1; i >= 0; i--) {
            IModification iMod = iModifications.get(i);
            if (iMod.instructionAddr < currentAddr && "LD_I".equals(iMod.instructionType)) {
                return iMod.iValue;
            }
        }
        return null;
    }

    /**
     * Find the value in Vx register by looking for preceding LD Vx, nn.
     */
    private int findPrecedingVxValue(Program program, long currentAddr, int vxRegister) {
        Listing listing = program.getListing();
        
        try {
            Address addrObj = program.getAddressFactory().getDefaultAddressSpace().getAddress(currentAddr);
            
            // Search backwards for LD Vx, nn instruction
            for (int i = 0; i < 50; i++) { // Search up to 50 instructions back
                addrObj = addrObj.subtract(2);
                if (addrObj.getOffset() < 0x200) {
                    break;
                }
                
                Instruction instruction = listing.getInstructionAt(addrObj);
                if (instruction == null) {
                    continue;
                }
                
                if (isLoadVxInstruction(instruction, vxRegister)) {
                    return getLoadVxValue(instruction);
                }
            }
            
            // Common fallback values for sprite operations
            return 8; // Often used for 8-pixel wide sprite offsets
            
        } catch (Exception e) {
            return 8;
        }
    }

    /**
     * Create sprites based on I-to-DRW associations.
     */
    private void createSpritesFromAssociations(Program program, MessageLog log) {
        Set<Long> createdSprites = new HashSet<>();
        
        for (SpriteAssociation assoc : spriteAssociations) {
            // Skip duplicates at same address
            if (createdSprites.contains(assoc.iValue)) {
                continue;
            }
            
            if (!isValidSpriteLocation(program, assoc.iValue)) {
                continue;
            }
            
            try {
                Address addrObj = program.getAddressFactory().getDefaultAddressSpace().getAddress(assoc.iValue);
                List<Integer> spriteData = readSpriteData(program, assoc.iValue, assoc.spriteHeight);
                
                if (spriteData == null || spriteData.size() != assoc.spriteHeight) {
                    continue;
                }
                
                // Skip sprites that are entirely null bytes
                if (spriteData.stream().allMatch(b -> b == 0)) {
                    continue;
                }
                
                createGhidraDataStructure(program, addrObj, assoc.spriteHeight);
                addSpriteComments(program, addrObj, spriteData, assoc);
                System.out.println(String.format(
                    "Created sprite at 0x%03X, height %d (I from 0x%03X, DRW at 0x%03X)",
                    assoc.iValue, assoc.spriteHeight, assoc.iAddr, assoc.drwAddr));
                
                createdSprites.add(assoc.iValue);
                
            } catch (Exception e) {
                System.out.println(String.format("Error creating sprite at 0x%03X: %s", assoc.iValue, e.getMessage()));
            }
        }
    }

    /**
     * Check if address points to valid sprite data (not instructions).
     */
    private boolean isValidSpriteLocation(Program program, long address) {
        if (address < 0x200 || address >= 4096) {
            return false;
        }
        
        Listing listing = program.getListing();
        try {
            Address addrObj = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            // If there's an instruction at this address, it's not sprite data
            return listing.getInstructionAt(addrObj) == null;
        } catch (Exception e) {
            return false;
        }
    }

    // --- Instruction Detection Methods ---

    private boolean isAddIInstruction(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                return (bytes[0] & 0xF0) == 0xF0 && (bytes[1] & 0xFF) == 0x1E;
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    private Integer getAddIRegister(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                return bytes[0] & 0x0F;
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private boolean isLoadVxInstruction(Instruction instruction, int targetRegister) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                if ((bytes[0] & 0xF0) == 0x60) { // LD Vx, nn pattern
                    int register = bytes[0] & 0x0F;
                    return register == targetRegister;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    private int getLoadVxValue(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                return bytes[1] & 0xFF;
            }
        } catch (Exception e) {
            // Ignore
        }
        return 0;
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
            // Ignore
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
    
    private void addSpriteComments(Program program, Address startAddr, List<Integer> spriteData, SpriteAssociation assoc) {
        Listing listing = program.getListing();
        
        // Add header comment with association information
        String headerComment = String.format("Sprite 0x%03X (%dx8) - I set at 0x%03X, DRW at 0x%03X", 
                assoc.iValue, spriteData.size(), assoc.iAddr, assoc.drwAddr);
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
                // Ignore comment errors on individual rows
            }
        }
    }
}
