
# -------------------------------------------------------------------------------
# Description: This module provides functionalities for binary file operations 
# 
#
# Author:      Prabhu Desai
# Email:       pdesai@one.ai
# 
# -------------------------------------------------------------------------------
import os
import shutil
class BinaryFileIO:
    version="0.1"
    data_layout = {
        #Index            START  LEN  DEFAULT_VALUE                
        'MAGIC_HDR'     : (0x0,  0x4  ,bytearray([0xC0,0xFF,0xEE,0xEE])),
        'ROLLBACK_VER'  : (0x08, 0x4  ,bytearray([0x00,0x00,0x00,0xFE])),    
        'FILE_LENGTH'   : (0x0c, 0x4  ,bytearray([0x00,0x00,0x00,0x00])),
        'HASH'          : (0x10, 0x20 ,'Hash Section'),
        'SW_VERSION'    : (0x50, 0x4  ,bytearray([0x1,0x2,0x3,0x4])),
        'DEMO_STAMP'    : (0x60, 0x30 ,bytearray([0x21,0x21,0x20,0x57,0x41,0x52,0x4E,0x49,0x4E,0x47,0x3A,0x20,0x20,0x20,0x20,0x20,0x20,0x53,0x69,0x67,0x6E,0x65,0x64,0x20,0x77,0x69,0x74,0x68,0x20,0x20,0x20,0x20,0x20,0x44,0x45,0x4D,0x4F,0x20,0x4B,0x45,0x59,0x53,0x20,0x20,0x20,0x21,0x21,0x20])),
        'SIGNATURE'     : (0x100,0x100,'Signature Section'),
        'CODE'          : (0x200,'FILE_LENGTH','Code Section'),#Notice the CODE_LENGTH is always 1 more , in this case 0x300 length will read from 0x200-0x2FF
    } 
    def __init__(self, file_path):
        self.file_path = file_path
        self.copy_file_path = None
    # Note: Each method accepts a bytearray as input and returns a bytearray as output.
    #       Conversion to the suitable format for display on the screen may be required.

    def read(self, start_address, length):
       
        with open(self.file_path, 'rb') as file:
            file.seek(start_address)
            retval=bytearray(file.read(length))
            file.close()
            return retval
        
    def create_copy(self):
        destination_folder="download"
        os.makedirs(destination_folder, exist_ok=True)
        copy_file_path = os.path.join(destination_folder, f"signed_{os.path.basename(self.file_path)}")
        shutil.copyfile(self.file_path, copy_file_path)
        #IMPORTANT : delete the orignal uploaded file and keep only the copied file.
        os.remove(self.file_path)
        self.copy_file_path = copy_file_path
 
    def update_signature(self, signature_val):
        with open(self.copy_file_path, 'r+b') as file:
            file.seek(self.data_layout['DEMO_STAMP'][0])
            file.write(self.data_layout['DEMO_STAMP'][2])
            file.seek(self.data_layout['SIGNATURE'][0])
            file.write(signature_val)
            file.close()
    
    def validate_binary(self):
        # Check if the file has a binary extension
        _, file_extension = os.path.splitext(self.file_path)
        if file_extension.lower() not in ['.bin']:
            print("Validation failed: The file does not have a valid binary extension.")
            return False

        # Read the first 4 bytes from the file
        header = self.get_header_field('MAGIC_HDR')
        # Read the first 4 bytes from the file
        rollback_id = self.get_header_field('ROLLBACK_VER')
        # Check if the header matches the expected pattern
        if (header == bytearray([0xC0, 0xFF, 0xEE, 0xEE]))and (rollback_id != bytearray([0xFF, 0xFF, 0xFF, 0xFF])):
            print("Validation successful: The file has the expected header.")
            return True
        else:
            print("Validation failed: The file does not have the expected header.")
            return False
    #Generic method to read MAGIC_HDR, ROLLBACK_VER , FILE_LENGTH, HASH, SW_VERSION, SIGNATURE
    def get_header_field(self,param):
        if param in self.data_layout:
            start, length, default_value = self.data_layout[param]
            print(param, start , length)
            return self.read(start, length)
        else:
            print(f"Invalid index: {param}. Please provide a valid index.")
            return None        
    
    def get_file_length(self):
        return int.from_bytes(self.get_header_field('FILE_LENGTH'), byteorder='big')
    
    def get_code(self):
        start_code, length, default_value = self.data_layout['CODE']
        return   self.read(start_code, self.get_file_length())     

    def print_bytearray(self, byte_array_in):
        hex_string = ' '.join(format(byte, '02X') for byte in byte_array_in)
        print("Hexadecimal representation of the byte array:")
        print(hex_string)
 
# #  usage:

# # Assuming you have a file named 'test.bin'
# file_path = 'test.bin'

# # Create an instance of BinaryFileIO
# binary_file = BinaryFileIO(file_path)

# # Read 16 bytes starting from address 0x100
# start_address = 0x200
# length = 16
# data_at_0x100 = binary_file.read(start_address, length)

# # Print the original data at 0x100
# binary_file.print_bytearray(data_at_0x100)

# # Modify the 16 bytes at 0x100 to be all 0x00
# new_value = bytearray([0x00] * length)
# binary_file.write_section(start_address, new_value)

# # Read and print the modified data at 0x100
# modified_data_at_0x100 = binary_file.read(start_address, length)
# binary_file.print_bytearray(modified_data_at_0x100)


 


