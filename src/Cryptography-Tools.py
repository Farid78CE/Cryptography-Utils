from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
from conversions import Conversions
import argparse

# Symmertic Cryptography
class AES:
    def __init__(self, conv):
        self.conv = conv

    def get_key_iv(self,):
        # it defines the number of bytes for key <256bits>
        key = os.urandom(32)
        # it defines the number of bytes for initialization vector <128bits>
        iv = os.urandom(16)

        return (key, iv)

    def craft_cipher(self, key, iv):
        # crafting encryption algorithm with its mode 
        # backend function provides a default backend for cryptographic operations, such as encryption and decryption.
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend) 
        return cipher
    

    def plaintext_source(self,):        
        parser = argparse.ArgumentParser(description="Specifying the source of plaintext")
        parser.add_argument('src', type=str, help="Specify Source", choices=['input', 'path'])
        parser.add_argument('value', type=str, help='plaintext value/File Path Address')
        args = parser.parse_args()


        if args.src == 'input':
            return self.conv.str_bytes(args.value)
        elif args.src == 'path':
            if os.path.exists(args.value):
                with open(args.value, 'r') as file:
                    content = file.read()
                    return self.conv.str_bytes(content)
            else:
                print(f"Error: file {args.value} does not exist!")


    def padding(self, plaintext):
        # specify how many bytes for padding is needed for arbitrary plaintext
        padding_length = 16 - len(plaintext) % 16 

        # this is a PKCS7 padding method
        padding_values = bytes([padding_length] * padding_length) 
        '''
         How it happens with 
                # plaintext=b"Test":
                # padding_length is 12
                # [padding_length] * padding_length creates the list [12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12]
                # bytes([12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12]) creates the bytes object b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
                # padding is b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
                # padded_plaintext is b'Test\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
        '''
        padded_plaintext = plaintext + padding_values
        return padded_plaintext

    
    def unpadding(self, padded_plaintext):
        # get the last element of byten value
        # for example: b'Hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
        # 0x0b = 11 integer
        padded_length = padded_plaintext[-1]
        # specify the real index or length of plaintext
        real_length = len(padded_plaintext) - padded_length
        
        plaintext = padded_plaintext[0: real_length]
        return plaintext

    
    def encrypt(self,):
       
        (key,  iv)= self.get_key_iv()
        cipher = self.craft_cipher(key, iv)
        encryptor = cipher.encryptor()
        # plaintext = b"Secret Messaage must be transmitted securely to the remote"
        plaintext = self.plaintext_source()
        padded_plaintext = self.padding(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        print(f"ciphertext: {self.conv.bytes_hex(ciphertext)}")
        return (ciphertext, key, iv)
        

    def decrypt(self, ciphertext, key, iv):
        cipher = self.craft_cipher(key, iv)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpadding(padded_plaintext)
        print(f"plaintext: {self.conv.bytes_str(plaintext)}")      
        return plaintext

class SHA256:
    def __init__(self, conv):
        self.conv = conv
        
    def hash():
        argparse.ArgumentParser(description="")
        hashes.SHA256
        

# # Assymetric Cryptography
# class RSA:
#     def __init__(self):
#         pass


if __name__ == '__main__':
    conv = Conversions()
    aes = AES(conv)
    (ciphertext, key, iv) =  aes.encrypt()
    aes.decrypt(ciphertext, key, iv)