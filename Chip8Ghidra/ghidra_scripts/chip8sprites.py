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
from java.util import ArrayList
from java.util import HashSet

class Chip8SpriteDetector(GhidraScript):
    
    def __init__(self):
        self.drw_instructions = []
        self.potential_sprite_addresses = {}
        self.analyzed_addresses = HashSet()
        
        
    def run(self):
        print("Starting CHIP-8 Sprite Detection...")
        
        # Step 1: Find all DRW instructions
        self.find_drw_instructions()
        print("DRW instructions:", self.drw_instructions)
        
        # Step 2: Analyze possible I register values for each DRW
        self.get_potential_sprite_addresses()
        formatted_addresses = {}
        for drw_addr, info in self.potential_sprite_addresses.items():
            formatted_addresses[drw_addr] = {
                'sprite_height': info['sprite_height'],
                'possible_i_values': [hex(addr) for addr in info['possible_i_values']]
            }
        print("Potential sprite addresses:", formatted_addresses)
        
        # Step 3: Create sprite data structuresa
        self.create_sprite_data_structures()
        
        print("Sprite detection complete.")
        
        
    def find_drw_instructions(self):
        print("Searching for DRW instructions...")
        
        # Get program memory
        memory = currentProgram.getMemory()
        listing = currentProgram.getListing()
        
        # Search through all instructions
        instruction_iter = listing.getInstructions(True)
        
        for instruction in instruction_iter:
            # Check if DRW
            if self.is_drw_instruction(instruction):
                self.drw_instructions.append(instruction)
                print("Found DRW at: " + str(instruction.getAddress()))
                
        print("# of DRW instructions found:", len(self.drw_instructions))


    def is_drw_instruction(self, instruction):
        if instruction is None:
            return False
                
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                # check if first nibble is 0xD
                first_byte = bytes_data[0] & 0xFF
                return (first_byte & 0xF0) == 0xD0
        except:
            pass
    
    
    def get_potential_sprite_addresses(self):
        print("Analyzing I register values for each DRW...")
        
        for drw_instruction in self.drw_instructions:
            print("Analyzing DRW at:", str(drw_instruction.getAddress()))
            
            sprite_height = self.get_sprite_height(drw_instruction)
            
            i_values = self.find_i_register_values()
            
            drw_addr = str(drw_instruction.getAddress())
            self.potential_sprite_addresses[drw_addr] = {
                'sprite_height': sprite_height,
                'possible_i_values': i_values
            }


    def get_sprite_height(self, drw_instruction):
        try:
            bytes_data = drw_instruction.getBytes()
            if len(bytes_data) >= 2:
                # Height is the last nibble (n in Dxyn)
                return bytes_data[1] & 0x0F
        except:
            pass
        return 1
    
    
    def find_i_register_values(self):
        i_addresses = set()
        
        listing = currentProgram.getListing()
        
        # Get all instructions
        instruction_iter = listing.getInstructions(True)  # True = forward direction
        instructions = [inst for inst in instruction_iter]
        
        # Check if each instruction is a LD I instruction; i.e. potential sprite addr
        for instruction in instructions:
            if self.is_load_i_instruction(instruction):
                addr_value = self.get_load_i_address(instruction)
                if addr_value is not None:
                    i_addresses.add(addr_value)
                    print("    Found LD I, 0x{:03X} at 0x{}".format(addr_value, str(instruction.getAddress())))
        
        return i_addresses


    def is_load_i_instruction(self, instruction):
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                first_byte = bytes_data[0] & 0xFF
                return (first_byte & 0xF0) == 0xA0  # A in first nibble
        except:
            pass
        return False


    def get_load_i_address(self, instruction):
        try:
            bytes_data = instruction.getBytes()
            if len(bytes_data) >= 2:
                # Address is the last 12 bits (nnn in Annn)
                addr = ((bytes_data[0] & 0x0F) << 8) | (bytes_data[1] & 0xFF)
                return addr
        except:
            pass
        return None
    
    
    def create_sprite_data_structures(self):
        print("Creating sprite data structures...")
        
        for drw_addr, info in self.potential_sprite_addresses.items():
            sprite_height = info['sprite_height']
            possible_addresses = info['possible_i_values']
            
            for sprite_addr in possible_addresses:
                if sprite_addr not in self.analyzed_addresses:
                    self.analyze_and_create_sprite(sprite_addr, sprite_height)


    def analyze_and_create_sprite(self, address, height):
        self.analyzed_addresses.add(address)
        
        try:
            addr_obj = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address)
            sprite_data = self.read_sprite_data(addr_obj, height)
            
            if sprite_data and self.is_valid_sprite_data(sprite_data, addr_obj, height):
                self.create_ghidra_data_structure(addr_obj, height)
                self.add_sprite_comments(addr_obj, sprite_data, address)
                print("Created sprite at 0x{:03X}, height {}".format(address, height))
        except Exception as e:
            print("Error creating sprite at 0x{:03X}: {}".format(address, str(e)))


    def read_sprite_data(self, addr_obj, height):
        sprite_data = []
        memory = currentProgram.getMemory()
        
        for i in range(height):
            try:
                byte_val = memory.getByte(addr_obj.add(i)) & 0xFF
                sprite_data.append(byte_val)
            except:
                return None  # Can't read memory
        
        return sprite_data


    def is_valid_sprite_data(self, sprite_data, addr_obj, height):
        if not sprite_data:
            return False
        
        # Check if any of the sprite bytes are already instructions
        listing = currentProgram.getListing()
        for i in range(height):
            check_addr = addr_obj.add(i)
            existing_instruction = listing.getInstructionAt(check_addr)
            if existing_instruction is not None:
                print("Skipping sprite at 0x{:03X} - contains instruction at 0x{:03X}".format(
                    addr_obj.getOffset(), check_addr.getOffset()))
                return False  # Not valid sprite data if it contains instructions
        
        return True

    def create_ghidra_data_structure(self, addr_obj, height):
        data_manager = currentProgram.getDataTypeManager()
        listing = currentProgram.getListing()
        
        try:
            byte_type = data_manager.getDataType("/byte")
            if byte_type is None:
                byte_type = ByteDataType()
        except:
            byte_type = ByteDataType()
        
        # Clear any existing data (safe since validation already checked for instructions)
        listing.clearCodeUnits(addr_obj, addr_obj.add(height - 1), False)
        
        # Create individual byte data structures instead of an array
        for i in range(height):
            byte_addr = addr_obj.add(i)
            listing.createData(byte_addr, byte_type)
        
        # Create a label for the sprite (only at the start)
        symbol_table = currentProgram.getSymbolTable()
        sprite_name = "SPRITE_0x{:03X}".format(addr_obj.getOffset())
        symbol_table.createLabel(addr_obj, sprite_name, SourceType.USER_DEFINED)


    def add_sprite_comments(self, start_addr, sprite_data, base_address):
        listing = currentProgram.getListing()
        
        # Add a header comment for the sprite
        header_comment = "Sprite 0x{:03X} ({}x8):".format(base_address, len(sprite_data))
        try:
            listing.setComment(start_addr, CodeUnit.PRE_COMMENT, header_comment)
        except:
            pass
        
        # Add individual row comments
        for i, byte_val in enumerate(sprite_data):
            try:
                row_addr = start_addr.add(i)
                
                # Create visual representation using ASCII characters
                visual_row = ""
                for bit in range(8):
                    if byte_val & (0b10000000 >> bit):
                        visual_row += "#"  # Filled pixel
                    else:
                        visual_row += "."  # Empty pixel
                
                # Create the comment with hex value and visualization
                comment = "0x{:02X} |{}| Row {}".format(byte_val, visual_row, i)
                
                # Add as end-of-line comment
                listing.setComment(row_addr, CodeUnit.EOL_COMMENT, comment)
                
            except Exception as e:
                print("Error adding comment at row {}: {}".format(i, str(e)))


script = Chip8SpriteDetector()
script.run()