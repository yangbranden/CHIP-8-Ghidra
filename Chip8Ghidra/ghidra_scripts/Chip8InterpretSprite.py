# CHIP-8 Manual Sprite Creator
# @category CHIP8
# @keybinding ctrl alt shift M
# @menupath Tools.CHIP8.Create Sprite at Cursor

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import *
from ghidra.program.model.address import *
from ghidra.program.model.mem import *
from ghidra.program.model.data import *
from ghidra.program.model.symbol import *
from ghidra.util.data.DataTypeParser import *

class Chip8ManualSpriteCreator(GhidraScript):
    
    def run(self):
        # Get the current cursor address
        current_addr = currentLocation.getAddress() if currentLocation else None
        
        if current_addr is None:
            popup("No address selected. Please place cursor at desired sprite location.")
            return
        
        # Prompt user for sprite height
        sprite_height = askInt("Sprite Height", "Enter the height of the sprite (1-15 pixels):")
        
        if sprite_height < 1 or sprite_height > 15:
            popup("Invalid height. Sprite height must be between 1 and 15.")
            return
        
        # Validate the address range
        if not self.is_valid_address_range(current_addr, sprite_height):
            popup("Invalid address range. Cannot create sprite of height {} at address 0x{:X}.".format(
                sprite_height, current_addr.getOffset()))
            return
        
        try:
            # Read the sprite data
            sprite_data = self.read_sprite_data(current_addr, sprite_height)
            if sprite_data is None:
                popup("Failed to read sprite data from memory.")
                return
            
            # Create the sprite
            self.create_sprite(current_addr, sprite_height, sprite_data)
            
            print("Successfully created sprite at 0x{:03X} with height {}".format(
                current_addr.getOffset(), sprite_height))
            
            # Show sprite preview in console
            self.print_sprite_preview(sprite_data, current_addr.getOffset())
            
        except Exception as e:
            popup("Error creating sprite: {}".format(str(e)))
    
    def is_valid_address_range(self, start_addr, height):
        """Check if the address range is valid for sprite creation."""
        try:
            # Check bounds
            if start_addr.getOffset() + height > 4096:  # CHIP-8 memory limit
                return False
            
            # Check if any bytes in the range are instructions
            listing = currentProgram.getListing()
            for i in range(height):
                addr = start_addr.add(i)
                if listing.getInstructionAt(addr) is not None:
                    # Ask user if they want to override instructions
                    response = askYesNo("Instruction Conflict", 
                        "Address 0x{:X} contains an instruction. Continue anyway?".format(addr.getOffset()))
                    if not response:
                        return False
            
            return True
            
        except Exception as e:
            return False
    
    def read_sprite_data(self, start_addr, height):
        """Read sprite data from memory."""
        try:
            sprite_data = []
            memory = currentProgram.getMemory()
            
            for i in range(height):
                addr = start_addr.add(i)
                byte_val = memory.getByte(addr) & 0xFF
                sprite_data.append(byte_val)
            
            return sprite_data
            
        except Exception as e:
            print("Error reading sprite data: {}".format(str(e)))
            return None
    
    def create_sprite(self, start_addr, height, sprite_data):
        """Create the sprite data structure in Ghidra."""
        data_manager = currentProgram.getDataTypeManager()
        listing = currentProgram.getListing()
        
        # Get byte data type
        try:
            byte_type = data_manager.getDataType("/byte")
            if byte_type is None:
                byte_type = ByteDataType()
        except:
            byte_type = ByteDataType()
        
        # Clear any existing data/code units
        end_addr = start_addr.add(height - 1)
        listing.clearCodeUnits(start_addr, end_addr, False)
        
        # Create byte data for each row
        for i in range(height):
            row_addr = start_addr.add(i)
            listing.createData(row_addr, byte_type)
        
        # Create a label for the sprite
        symbol_table = currentProgram.getSymbolTable()
        sprite_name = "SPRITE_0x{:03X}".format(start_addr.getOffset())
        
        try:
            # Remove any existing symbol at this address first
            existing_symbols = symbol_table.getSymbols(start_addr)
            for symbol in existing_symbols:
                if symbol.getSource() == SourceType.ANALYSIS:
                    symbol_table.removeSymbolSpecial(symbol)
            
            symbol_table.createLabel(start_addr, sprite_name, SourceType.USER_DEFINED)
        except Exception as e:
            print("Warning: Could not create label: {}".format(str(e)))
        
        # Add comments
        self.add_sprite_comments(start_addr, sprite_data)
    
    def add_sprite_comments(self, start_addr, sprite_data):
        """Add visual comments to the sprite data."""
        listing = currentProgram.getListing()
        
        # Header comment
        header_comment = "Manual Sprite 0x{:03X} ({}x8)".format(
            start_addr.getOffset(), len(sprite_data))
        
        try:
            listing.setComment(start_addr, CodeUnit.PRE_COMMENT, header_comment)
        except Exception as e:
            print("Warning: Could not set header comment: {}".format(str(e)))
        
        # Row comments with visual representation
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
                print("Warning: Could not set row comment for row {}: {}".format(i, str(e)))
    
    def print_sprite_preview(self, sprite_data, base_address):
        """Print a preview of the sprite to console."""
        print("\nSprite Preview for 0x{:03X}:".format(base_address))
        print("+" + "-" * 8 + "+")
        
        for i, byte_val in enumerate(sprite_data):
            visual_row = ""
            for bit in range(8):
                if byte_val & (0b10000000 >> bit):
                    visual_row += "#"
                else:
                    visual_row += "."
            
            print("|{}| 0x{:02X}".format(visual_row, byte_val))
        
        print("+" + "-" * 8 + "+")

# Run the script
script = Chip8ManualSpriteCreator()
script.run()
