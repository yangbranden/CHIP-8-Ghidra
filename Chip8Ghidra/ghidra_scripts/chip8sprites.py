# CHIP-8 Sprite Detector
# @category CHIP8
# @keybinding ctrl alt shift S
# @menupath Tools.CHIP8.Detect Sprites

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import *
from ghidra.program.model.address import *
from ghidra.program.model.mem import *
from ghidra.program.model.data import *
from ghidra.program.model.symbol import *
from ghidra.util.data.DataTypeParser import *
from java.util import HashSet

class Chip8SpriteDetector(GhidraScript):
    
    def __init__(self):
        self.candidate_sprite_addresses = set()
        self.candidate_sprite_lengths = set()
        self.best_fit_sprites = {}
    
    def run(self):
        print("Starting CHIP-8 Sprite Detection...")
        
        # Step 1: Find all candidate sprite addresses and lengths from instructions
        self.find_candidates()
        print("Found {} candidate addresses and {} candidate lengths.".format(
            len(self.candidate_sprite_addresses), len(self.candidate_sprite_lengths)))
        
        # Step 2: For each candidate address, determine the best-fit sprite length
        self.determine_best_fit_sprites()
        print("Determined {} best-fit sprites.".format(len(self.best_fit_sprites)))
        
        # Step 3: Create Ghidra data structures for the identified best-fit sprites
        self.create_ghidra_structures_for_best_fit()
        
        print("Sprite detection complete.")
    
    def find_candidates(self):
        """Scans the program for LD I, addr and DRW instructions to populate candidate lists."""
        self.candidate_sprite_addresses.clear()
        self.candidate_sprite_lengths.clear()
        
        listing = currentProgram.getListing()
        instruction_iter = listing.getInstructions(True)
        
        for instruction in instruction_iter:
            if self.is_load_i_instruction(instruction):
                addr_value = self.get_load_i_address(instruction)
                if addr_value is not None:
                    self.candidate_sprite_addresses.add(addr_value)
            elif self.is_drw_instruction(instruction):
                sprite_height = self.get_sprite_height(instruction)
                if sprite_height > 0:  # Valid sprites have height > 0
                    self.candidate_sprite_lengths.add(sprite_height)
    
    def determine_best_fit_sprites(self):
        """Iterates through candidate addresses and lengths to find the optimal length for each address.
        The best fit is the one with the fewest null bytes."""
        self.best_fit_sprites.clear()
        
        for address in self.candidate_sprite_addresses:
            best_length = -1
            min_null_bytes = float('inf')
            
            for length in self.candidate_sprite_lengths:
                if not self.is_valid_potential_sprite(address, length):
                    continue
                
                sprite_data = self.read_sprite_data_by_address(address, length)
                if sprite_data is None or len(sprite_data) != length:
                    continue  # Skip if data can't be read fully
                
                null_byte_count = self.count_null_bytes(sprite_data)
                
                # A sprite made entirely of null bytes is invalid
                if null_byte_count == length:
                    continue
                
                # Lower null byte count is a better fit
                if null_byte_count < min_null_bytes:
                    min_null_bytes = null_byte_count
                    best_length = length
            
            if best_length != -1:
                self.best_fit_sprites[address] = best_length
    
    def create_ghidra_structures_for_best_fit(self):
        """Creates Ghidra data types, labels, and comments for the final best-fit sprites."""
        sorted_addresses = sorted(self.best_fit_sprites.keys())
        
        for address in sorted_addresses:
            height = self.best_fit_sprites[address]
            try:
                addr_obj = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address)
                
                sprite_data = self.read_sprite_data(addr_obj, height)
                if sprite_data is None:
                    continue
                
                self.create_ghidra_data_structure(addr_obj, height)
                self.add_sprite_comments(addr_obj, sprite_data, address)
                print("Created sprite at 0x{:03X}, height {}".format(address, height))
                
            except Exception as e:
                print("Error creating sprite at 0x{:03X}: {}".format(address, str(e)))
    
    # --- Helper and Utility Methods ---
    
    def count_null_bytes(self, data):
        """Count the number of null bytes in the data."""
        return sum(1 for b in data if b == 0)
    
    def is_valid_potential_sprite(self, address, height):
        """Check if the address and height combination represents a valid potential sprite."""
        end_offset = address + height
        VALID_REGION_END = 4096  # CHIP-8 memory size
        
        if address < 0 or end_offset > VALID_REGION_END:
            return False
        
        listing = currentProgram.getListing()
        try:
            start_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address)
            for i in range(height):
                if listing.getInstructionAt(start_addr.add(i)) is not None:
                    return False  # Region overlaps with existing code
        except:
            return False
        
        return True
    
    def read_sprite_data_by_address(self, address, height):
        """Read sprite data from memory given an address and height."""
        try:
            addr_obj = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address)
            return self.read_sprite_data(addr_obj, height)
        except:
            return None
    
    def is_drw_instruction(self, instruction):
        """Check if the instruction is a DRW instruction."""
        if instruction is None:
            return False
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                first_byte = bytes_data[0] & 0xFF
                return (first_byte & 0xF0) == 0xD0
        except:
            pass
        return False
    
    def get_sprite_height(self, drw_instruction):
        """Extract sprite height from DRW instruction."""
        try:
            bytes_data = drw_instruction.getBytes()
            if len(bytes_data) >= 2:
                return bytes_data[1] & 0x0F
        except:
            pass
        return 0
    
    def is_load_i_instruction(self, instruction):
        """Check if the instruction is a LD I, addr instruction."""
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                first_byte = bytes_data[0] & 0xFF
                return (first_byte & 0xF0) == 0xA0
        except:
            pass
        return False
    
    def get_load_i_address(self, instruction):
        """Extract address from LD I, addr instruction."""
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                addr = ((bytes_data[0] & 0x0F) << 8) | (bytes_data[1] & 0xFF)
                return addr
        except:
            pass
        return None
    
    def read_sprite_data(self, addr_obj, height):
        """Read sprite data from memory."""
        sprite_data = []
        memory = currentProgram.getMemory()
        try:
            for i in range(height):
                byte_val = memory.getByte(addr_obj.add(i)) & 0xFF
                sprite_data.append(byte_val)
            return sprite_data
        except:
            return None
    
    def create_ghidra_data_structure(self, addr_obj, height):
        """Create Ghidra data structures for the sprite."""
        data_manager = currentProgram.getDataTypeManager()
        listing = currentProgram.getListing()
        
        try:
            byte_type = data_manager.getDataType("/byte")
            if byte_type is None:
                byte_type = ByteDataType()
        except:
            byte_type = ByteDataType()
        
        # Clear any existing data
        listing.clearCodeUnits(addr_obj, addr_obj.add(height - 1), False)
        
        # Create individual byte data structures
        for i in range(height):
            byte_addr = addr_obj.add(i)
            listing.createData(byte_addr, byte_type)
        
        # Create a label for the sprite
        symbol_table = currentProgram.getSymbolTable()
        sprite_name = "SPRITE_0x{:03X}".format(addr_obj.getOffset())
        symbol_table.createLabel(addr_obj, sprite_name, SourceType.ANALYSIS)
    
    def add_sprite_comments(self, start_addr, sprite_data, base_address):
        """Add comments to visualize the sprite data."""
        listing = currentProgram.getListing()
        
        # Add header comment
        header_comment = "Sprite 0x{:03X} ({}x8)".format(base_address, len(sprite_data))
        try:
            listing.setComment(start_addr, CodeUnit.PRE_COMMENT, header_comment)
        except:
            pass
        
        # Add individual row comments
        for i, byte_val in enumerate(sprite_data):
            try:
                row_addr = start_addr.add(i)
                # Create visual representation
                visual_row = ""
                for bit in range(8):
                    if byte_val & (0b10000000 >> bit):
                        visual_row += "#"  # Filled pixel
                    else:
                        visual_row += "."  # Empty pixel
                
                comment = "0x{:02X} |{}|".format(byte_val, visual_row)
                listing.setComment(row_addr, CodeUnit.EOL_COMMENT, comment)
            except Exception as e:
                # Ignore comment errors on individual rows
                pass

# Run the script
script = Chip8SpriteDetector()
script.run()
