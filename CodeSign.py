# -------------------------------------------------------------------------------
# Description: This module provides functionalities for code signing operations, 
# including key management, signature generation, verification, and hash calculation.
# 
#
# Author:      Prabhu Desai
# Email:       pdesai@one.ai
# 
# -------------------------------------------------------------------------------

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives import serialization

class CodeSign:
    version = "1.0"  # Class attribute for version information

    def __init__(self, private_key_file, public_key_file):
        # Initialize CodeSign object with private and public key files
        self.private_key = self.load_private_key_from_file(private_key_file)
        self.public_key = self.load_public_key_from_file(public_key_file)
    
    #Loads the private key from a PEM file. 
    # IMPORTANT : The private key is stored in the server in plain text 
    # and needs to be moved to KMS /HSM of AWS Cloud.
    def load_private_key_from_file(self, private_key_file):
        # Load private key from a file in PEM format
        with open(private_key_file, 'rb') as file:
            private_key_bytes = file.read()
            return serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )
    #Loads the public key from a PEM file
    def load_public_key_from_file(self, public_key_file):
        # Load public key from a file in PEM format
        with open(public_key_file, 'rb') as file:
            public_key_bytes = file.read()
            return x509.load_pem_x509_certificate(
                public_key_bytes,
                default_backend()
            ).public_key()

    # Note: Each method accepts a bytearray as input and returns a bytearray as output.
    # Conversion to the suitable format for display on the screen may be required.
    def calc_hash(self, data):
        # Calculate SHA256 hash of input data
        data_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        data_hash.update(data)
        return data_hash.finalize()

    def sign_hash(self, data_hash):
        # Sign a hash using the private key and return the signature as a bytearray
        signature = self.private_key.sign(
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return bytearray(signature)
    
    
    #Verifies a signature using the public key.
    def verify_signature(self, data_hash, signature):
        try:
            # Verify the signature using the public key
            signature_bytes = bytes(signature)
            self.public_key.verify(
                signature_bytes,
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid.")
            return True
        except Exception as e:
            print("Signature verification failed:", str(e))
            return False
        

    #Prints information about the private or public key in PEM format.
    def display_key_info(self, key_type):
        # Display information about the private or public key in PEM format
        print(f"{key_type} Key Information (PEM Format):")
        print("----------------------------")
        if key_type == "Private":
            print(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'))
        elif key_type == "Public":
            print(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'))



    #Converts a hex string to bytes. (Static method)
    @staticmethod
    def hex_string_to_bytes(hex_string):
        # Convert a hex string to bytes
        # Ensure the input has an even length
        if len(hex_string) % 2 != 0:
            raise ValueError("Hex string must have an even length")

        # Convert each pair of hex characters to a byte
        byte_array = bytearray.fromhex(hex_string)
        return bytes(byte_array)
