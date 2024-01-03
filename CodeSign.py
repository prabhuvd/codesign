import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CodeSign:
    version = "1.0"  # Class attribute for version information

    def __init__(self, private_key_file, public_key_file):
        self.private_key = self.load_private_key_from_file(private_key_file)
        self.public_key = self.load_public_key_from_file(public_key_file)

    def load_private_key_from_file(self, private_key_file):
        with open(private_key_file, 'rb') as file:
            private_key_bytes = file.read()
            return serialization.load_pem_private_key(
                private_key_bytes,
                password=None,
                backend=default_backend()
            )

    def load_public_key_from_file(self, public_key_file):
        with open(public_key_file, 'rb') as file:
            public_key_bytes = file.read()
            return x509.load_pem_x509_certificate(
                public_key_bytes,
                default_backend()
            ).public_key()

    # Note: Each method accepts a bytearray as input and returns a bytearray as output.
    #       Conversion to the suitable format for display on the screen may be required.
    def calc_hash(self, data):
        data_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        data_hash.update(data)
        return data_hash.finalize()

    def sign_hash(self, data_hash):
        signature = self.private_key.sign(
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return bytearray(signature)


    def verify_signature(self, data_hash, signature):
        try:
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

    def display_key_info(self, key_type):
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

    @staticmethod
    def hex_string_to_bytes(hex_string):
        # Ensure the input has an even length
        if len(hex_string) % 2 != 0:
            raise ValueError("Hex string must have an even length")

        # Convert each pair of hex characters to a byte
        byte_array = bytearray.fromhex(hex_string)
        return bytes(byte_array)



# Example usage:
# Example usage of CodeSign class

# # Paths to private and public key files
# private_key_file = "PrivKey_FIRMWARE.pem"
# public_key_file = "PubKey_FIRMWARE.crt"
# keys_folder = 'Keys'


# #Load the keys
# private_key_path = os.path.join(keys_folder,"PrivKey_FIRMWARE.pem")            
# public_key_path = os.path.join(keys_folder,"PubKey_FIRMWARE.crt")
# # Instantiate CodeSign class
# code_signer = CodeSign(private_key_path, public_key_path)

# # Data to be signed
# data_to_sign = b"Hello, World!"

# # Create a hash of the data
# data_hash = code_signer.calc_hash(data_to_sign)

# # Sign the hash
# signature = code_signer.sign_hash(data_hash)

# # Display information about the private key
# code_signer.display_key_info("Private")

# print("Hash value ",data_hash)
# print("Singature  ",signature)
# # Verify the signature
# if code_signer.verify_signature(data_hash, signature):
#     print("Signature verification successful.")
# else:
#     print("Signature verification failed.")
