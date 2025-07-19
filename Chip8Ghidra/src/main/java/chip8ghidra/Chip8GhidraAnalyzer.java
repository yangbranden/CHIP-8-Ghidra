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
 * by performing backwards data flow analysis from DRW instructions to find
 * all I register modifications that could reach them, with DRW boundary detection
 * and configurable instruction limit.
 */
public class Chip8GhidraAnalyzer extends AbstractAnalyzer {
    
    // Configuration options
    private static final String OPTION_MAX_BACKWARDS_INSTRUCTIONS = "Max Backwards Instructions";
    private static final String OPTION_MAX_BACKWARDS_INSTRUCTIONS_DESC = 
        "Maximum number of instructions to trace backwards from each DRW. " +
        "Lower values reduce false positives but may miss some sprites.";
    private static final int DEFAULT_MAX_BACKWARDS_INSTRUCTIONS = 50;
    
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
    private int maxBackwardsInstructions;
    
    public Chip8GhidraAnalyzer() {
        super("CHIP-8 Sprite Analyzer", 
            "Analyzes CHIP-8 code to find and define sprites using backwards data flow analysis " +
            "with DRW boundary detection and configurable instruction limit.", 
            AnalyzerType.BYTE_ANALYZER);
        iModifications = new ArrayList<>();
        drwInstructions = new ArrayList<>();
        spriteAssociations = new ArrayList<>();
        maxBackwardsInstructions = DEFAULT_MAX_BACKWARDS_INSTRUCTIONS;
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
        options.registerOption(OPTION_MAX_BACKWARDS_INSTRUCTIONS, 
            DEFAULT_MAX_BACKWARDS_INSTRUCTIONS, null, OPTION_MAX_BACKWARDS_INSTRUCTIONS_DESC);
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        
        // Get user options
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        maxBackwardsInstructions = options.getInt(OPTION_MAX_BACKWARDS_INSTRUCTIONS, DEFAULT_MAX_BACKWARDS_INSTRUCTIONS);
        
        System.out.println("Starting CHIP-8 Sprite Detection with backwards data flow analysis...");
        System.out.println(String.format("Max backwards instructions limit: %d", maxBackwardsInstructions));
        
        // Step 1: Find all DRW instructions FIRST
        findDrwInstructions(program, monitor);
        System.out.println(String.format("Found %d DRW instructions.", drwInstructions.size()));
        
        // Step 2: Find all instructions that modify I register
        findIModifications(program, monitor);
        System.out.println(String.format("Found %d I modification instructions.", iModifications.size()));
        
        // Step 3: Perform backwards data flow analysis from DRW to I modifications
        performBackwardsDataFlowAnalysis(program);
        System.out.println(String.format("Created %d I-to-DRW associations via data flow analysis.", spriteAssociations.size()));
        
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
                // For ADD I, Vx - calculate multiple resulting I values (for loops)
                Integer vxReg = getAddIRegister(instruction);
                if (vxReg != null) {
                    List<Long> iValues = calculateAddIResults(program, addr, vxReg);
                    for (Long iValue : iValues) {
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
     * Perform backwards data flow analysis from each DRW instruction to find
     * all I register modifications that could reach it through execution flow.
     * STOPS when encountering other DRW instructions (logical boundaries) or
     * when the instruction limit is reached.
     */
    private void performBackwardsDataFlowAnalysis(Program program) {
        spriteAssociations.clear();
        Listing listing = program.getListing();
        
        // For each DRW instruction, trace backwards to find all I modifications that could reach it
        for (DrwInstruction drw : drwInstructions) {
            Set<IModification> reachingIMods = new HashSet<>();
            Set<Long> visited = new HashSet<>();
            Deque<Long> worklist = new ArrayDeque<>();
            int instructionsProcessed = 0;
            
            worklist.add(drw.drwAddr);
            
            while (!worklist.isEmpty() && instructionsProcessed < maxBackwardsInstructions) {
                long currentAddr = worklist.pollFirst();
                
                if (visited.contains(currentAddr)) {
                    continue;
                }
                visited.add(currentAddr);
                instructionsProcessed++;
                
                // CRITICAL: Check if we hit another DRW instruction (boundary condition)
                if (currentAddr != drw.drwAddr && isDRWAddress(currentAddr)) {
                    System.out.println(String.format(
                        "Backwards analysis from DRW 0x%03X stopped at DRW boundary 0x%03X",
                        drw.drwAddr, currentAddr));
                    continue; // Don't traverse past other DRW instructions
                }
                
                // Check if any I modification happens at this address
                for (IModification iMod : iModifications) {
                    if (iMod.instructionAddr == currentAddr) {
                        reachingIMods.add(iMod);
                        System.out.println(String.format(
                            "Found I modification at 0x%03X (I=0x%03X) reaching DRW 0x%03X",
                            iMod.instructionAddr, iMod.iValue, drw.drwAddr));
                    }
                }
                
                // Add predecessors to worklist (only if we didn't hit a DRW boundary)
                addPredecessors(program, listing, currentAddr, worklist, visited);
            }
            
            // Report if we hit the instruction limit
            if (instructionsProcessed >= maxBackwardsInstructions) {
                System.out.println(String.format(
                    "Backwards analysis from DRW 0x%03X stopped at instruction limit (%d instructions)",
                    drw.drwAddr, maxBackwardsInstructions));
            }
            
            // Create associations for all reaching I modifications
            for (IModification iMod : reachingIMods) {
                spriteAssociations.add(new SpriteAssociation(
                    iMod.instructionAddr, iMod.iValue, drw.drwAddr, drw.spriteHeight));
                
                System.out.println(String.format(
                    "Data flow: I modification at 0x%03X (I=0x%03X) -> DRW at 0x%03X (height=%d)",
                    iMod.instructionAddr, iMod.iValue, drw.drwAddr, drw.spriteHeight));
            }
            
            System.out.println(String.format(
                "DRW at 0x%03X associated with %d I modifications (processed %d instructions)",
                drw.drwAddr, reachingIMods.size(), instructionsProcessed));
        }
    }
    
    /**
     * Helper method to check if an address contains a DRW instruction
     */
    private boolean isDRWAddress(long address) {
        for (DrwInstruction drwInstr : drwInstructions) {
            if (drwInstr.drwAddr == address) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Add predecessor addresses to the worklist for backwards data flow analysis.
     * This includes linear predecessors and jump/call sources.
     */
    private void addPredecessors(Program program, Listing listing, long currentAddr, 
                                Deque<Long> worklist, Set<Long> visited) {
        
        // Linear predecessor (instruction 2 bytes before)
        long prevAddr = currentAddr - 2;
        if (prevAddr >= 0x200 && !visited.contains(prevAddr)) { // CHIP-8 programs start at 0x200
            Instruction prevInstr = listing.getInstructionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(prevAddr));
            if (prevInstr != null) {
                worklist.add(prevAddr);
            }
        }
        
        // Find jump and call sources that could reach this address
        try {
            Address targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(currentAddr);
            ReferenceIterator refIterator = program.getReferenceManager().getReferencesTo(targetAddr);
            
            // Iterate through the references using the iterator
            while (refIterator.hasNext()) {
                Reference ref = refIterator.next();
                if (ref.getReferenceType().isJump() || ref.getReferenceType().isCall()) {
                    long sourceAddr = ref.getFromAddress().getOffset();
                    if (!visited.contains(sourceAddr)) {
                        worklist.add(sourceAddr);
                    }
                }
            }
        } catch (Exception e) {
            // Ignore reference lookup errors
        }
        
        // Handle conditional jumps and branches - add fall-through paths
        try {
            long fallThroughAddr = currentAddr - 2;
            if (fallThroughAddr >= 0x200 && !visited.contains(fallThroughAddr)) {
                Instruction fallThroughInstr = listing.getInstructionAt(
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(fallThroughAddr));
                if (fallThroughInstr != null && isConditionalInstruction(fallThroughInstr)) {
                    worklist.add(fallThroughAddr);
                }
            }
        } catch (Exception e) {
            // Ignore errors
        }
    }
    
    /**
     * Check if instruction is a conditional instruction (SE, SNE, etc.)
     */
    private boolean isConditionalInstruction(Instruction instruction) {
        try {
            byte[] bytes = instruction.getBytes();
            if (bytes.length >= 2) {
                int firstNibble = (bytes[0] & 0xF0) >> 4;
                // SE Vx, byte (3xkk), SNE Vx, byte (4xkk), SE Vx, Vy (5xy0), SNE Vx, Vy (9xy0)
                return firstNibble == 3 || firstNibble == 4 || firstNibble == 5 || firstNibble == 9;
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }
    
    /**
     * Calculate the resulting I values from ADD I, Vx instruction (for loop detection).
     * Keeps adding the offset until we hit an instruction or invalid address.
     */
    private List<Long> calculateAddIResults(Program program, long addIAddr, int vxRegister) {
        List<Long> results = new ArrayList<>();
        
        // First, find the preceding LD I instruction to get base I value
        Long baseIValue = findPrecedingLdI(addIAddr);
        if (baseIValue == null) {
            return results;
        }
        
        // Find the value in Vx register (the offset)
        int vxValue = findPrecedingVxValue(program, addIAddr, vxRegister);
        
        // Estimate sprite height for validation
        int estimatedHeight = estimateSpriteHeight(addIAddr);
        
        // Keep adding the offset until we hit an instruction or go out of bounds
        long currentIValue = baseIValue;
        int maxIterations = 50; // Prevent infinite loops
        
        for (int iteration = 1; iteration <= maxIterations; iteration++) {
            currentIValue += vxValue;
            
            // Check bounds
            if (currentIValue < 0x200 || currentIValue >= 4096) {
                break;
            }
            
            // Validate that result points to potential sprite data (not instructions)
            if (!isValidSpriteLocation(program, currentIValue, estimatedHeight)) {
                break;
            }
            
            // Check if the data at this location looks like sprite data
            if (isLikelyEmptyOrInvalidSprite(program, currentIValue)) {
                break;
            }
            
            results.add(currentIValue);
            System.out.println(String.format(
                "ADD I loop iteration %d: base=0x%03X + (%d * %d) = 0x%03X",
                iteration, baseIValue, iteration, vxValue, currentIValue));
        }
        
        System.out.println(String.format(
            "ADD I at 0x%03X generated %d potential sprite addresses",
            addIAddr, results.size()));
        return results;
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
            
            // Default sprite width fallback
            return 8; // Most common sprite width
        } catch (Exception e) {
            return 8;
        }
    }
    
    /**
     * Estimate sprite height for ADD I validation by looking at nearby DRW instructions.
     */
    private int estimateSpriteHeight(long addIAddr) {
        // Find the closest DRW instruction to estimate sprite height
        int closestHeight = 15; // Maximum CHIP-8 sprite height as default fallback
        long minDistance = Long.MAX_VALUE;
        
        for (DrwInstruction drw : drwInstructions) {
            long distance = Math.abs(drw.drwAddr - addIAddr);
            if (distance < minDistance) {
                minDistance = distance;
                closestHeight = drw.spriteHeight;
            }
        }
        
        return closestHeight;
    }
    
    /**
     * Check if the address likely contains empty or invalid sprite data.
     */
    private boolean isLikelyEmptyOrInvalidSprite(Program program, long address) {
        try {
            Memory memory = program.getMemory();
            Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            
            // Read a few bytes to check if they look like valid sprite data
            int bytesToCheck = Math.min(8, (int)(4096 - address));
            int nullBytes = 0;
            int totalBytes = 0;
            
            for (int i = 0; i < bytesToCheck; i++) {
                try {
                    byte byteVal = memory.getByte(startAddr.add(i));
                    totalBytes++;
                    if ((byteVal & 0xFF) == 0) {
                        nullBytes++;
                    }
                } catch (Exception e) {
                    break;
                }
            }
            
            // If more than 75% of bytes are null, likely not a sprite
            if (totalBytes > 0 && (double)nullBytes / totalBytes > 0.75) {
                return true;
            }
            
            // Additional check: if we're reading all 0xFF bytes, might be uninitialized memory
            try {
                byte firstByte = memory.getByte(startAddr);
                byte secondByte = memory.getByte(startAddr.add(1));
                if ((firstByte & 0xFF) == 0xFF && (secondByte & 0xFF) == 0xFF) {
                    return true;
                }
            } catch (Exception e) {
                return true;
            }
            
            return false;
        } catch (Exception e) {
            return true;
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
            
            // Check with the actual sprite height
            if (!isValidSpriteLocation(program, assoc.iValue, assoc.spriteHeight)) {
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
     * This checks the ENTIRE sprite range, not just the starting address.
     */
    private boolean isValidSpriteLocation(Program program, long address, int height) {
        if (address < 0x200 || address + height > 4096) {
            return false;
        }
        
        Listing listing = program.getListing();
        try {
            Address startAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            
            // Check EVERY byte in the sprite range for instructions
            for (int i = 0; i < height; i++) {
                Address currentAddr = startAddr.add(i);
                if (listing.getInstructionAt(currentAddr) != null) {
                    System.out.println(String.format(
                        "Sprite at 0x%03X (height %d) overlaps with instruction at 0x%03X - skipping",
                        address, height, currentAddr.getOffset()));
                    return false;
                }
            }
            
            return true;
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
