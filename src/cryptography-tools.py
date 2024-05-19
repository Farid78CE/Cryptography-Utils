from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
from conversions import Conversions
import argparse
from datetime import datetime

# Symmertic Cryptography
class AES:
    def __init__(self, conv):
        self.conv = conv

    def generate_key_iv(self,):
        # it defines the number of bytes for key <256bits>
        key = os.urandom(32)
        # it defines the number of bytes for initialization vector <128bits>
        iv = os.urandom(16)

        return (key, iv)

    def craft_AES_cipher(self, key, iv):
        # crafting encryption algorithm with its mode 
        # backend function provides a default backend for cryptographic operations, such as encryption and decryption.
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend) 
        return cipher

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
    
    def encrypt(self, plaintext):
        (key,  iv)= self.generate_key_iv()
        cipher = self.craft_AES_cipher(key, iv)
        encryptor = cipher.encryptor()
        # plaintext = b"Secret Messaage must be transmitted securely to the remote"
        padded_plaintext = self.padding(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        self.store_key(key, iv)
        return (ciphertext, key, iv)

    def decrypt(self, ciphertext, key, iv):
        cipher = self.craft_AES_cipher(key, iv)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpadding(padded_plaintext)
        return plaintext

    def store_key(self, key, iv):
        cwd = os.getcwd()
        full_time = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        path = cwd + "\\key " + full_time
        key  = self.conv.bytes_hex(key); iv = self.conv.bytes_hex(iv)
        try:
            with open(path, "a") as file:
                file.write(key); file.write("\n") ; file.write(iv)
        except Exception as e:
            print(e)
            
class SecureHash:
    def __init__(self, conv):
        self.conv = conv
        
    def select_hash_func(self, hash_type):
        
        digest: hashes.Hash
        
        if hash_type == "MD5":
            digest = hashes.Hash(hashes.MD5(),backend=default_backend)
        elif hash_type == "SHA1":
            digest = hashes.Hash(hashes.SHA1(),backend=default_backend)
        elif hash_type == "SHA384":
            digest = hashes.Hash(hashes.SHA384(),backend=default_backend)
        elif hash_type == "SHA512":
            digest = hashes.Hash(hashes.SHA512(),backend=default_backend)
        elif hash_type == "SHA3_256":
            digest = hashes.Hash(hashes.SHA3_256(),backend=default_backend)
        elif hash_type == "SHA3_384":
            digest = hashes.Hash(hashes.SHA3_384(),backend=default_backend)
        elif hash_type == "SHA3_512":
            digest = hashes.Hash(hashes.SHA3_512(),backend=default_backend)
        else:
            digest = hashes.Hash(hashes.SHA256(),backend=default_backend)
            
        return digest
    
    def cal_hash(self, path_or_data, hash_type, flag, chunck_size=8192):
        if flag:
            digest = self.select_hash_func(hash_type)
            with open(path_or_data, 'rb') as file:
                while chunck := file.read(chunck_size):
                    digest.update(chunck)

            hash_value = digest.finalize()
            return hash_value
        else:
            digest = self.select_hash_func(hash_type)
            digest.update(path_or_data)
            hash_value = digest.finalize()
            return hash_value

    def compare(self, ):
        pass
    
class CommandHandler:
    def AES_handler(self):
        pass
    
    def secure_hash_handler(self):
        pass
    
    def main(self):
        """
        formatter_class: Allows customization of the help message formatting. 
        argparse.ArgumentDefaultsHelpFormatter is used here to include default values in the help message.
        """
        parser = argparse.ArgumentParser(
            description="Cryptographic tool",
            epilog="Primitive cryptographic functions that is widely used",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        
        subparsers = parser.add_subparsers(dest="command", help="commands", description="All available commands")
        
        # AES commands 
        AES_parser = subparsers.add_parser("aes", description="AES256-CBC mode", help="AES encryption algorithm.")
        AES_parser.add_argument("cipher_or_decipher", type=str, choices=["encrypt", "decrypt"], help="Choose between encryption/decryption.")
        AES_parser.add_argument("path_or_data_enc", type=str, help="Plaintext value/file address")
        AES_parser.add_argument("--credentials", type=str, help="Credentials (key, iv) path")
        
        
        
        # SecureHash commands
        secure_hash_parser = subparsers.add_parser("secure_hash", description="Using different Hash function for getting message digest", help="Secure Hash functions")
        secure_hash_parser.add_argument("hash_type", type=str, choices=["MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512"])
        secure_hash_parser.add_argument("path_or_data_hash", type=str, help="plaintext value/File Address")
        secure_hash_parser.add_argument("--compare", type=str, help="compare calculated hash with official published hash")
        
          
        arg = parser.parse_args()
        
        conv = Conversions()
        
        # AES module
        if arg.command == "aes":
            aes = AES(conv)
            if arg.cipher_or_decipher == "encrypt":
                if os.path.exists(arg.path_or_data_enc):
                    with open(arg.path_or_data_enc, 'r') as file:
                        plaintext = file.read()
                        plaintext = conv.str_bytes(plaintext)
                        ciphertext, key, iv = aes.encrypt(plaintext)
                        print(f"ciphertext: {conv.bytes_hex(ciphertext)}")
                else:
                    plaintext = conv.str_bytes(arg.path_or_data_enc)
                    ciphertext, key, iv = aes.encrypt(plaintext)
                    print(f"ciphertext: {conv.bytes_hex(ciphertext)}")
            else:
                # decryption
                # D:\Eternal_Liberty_And_Glory\Source Codes\Cryptography\Cryptography-Utils\src\key 2024-05-17 22-36-16
                if arg.credentials is not None:
                    if os.path.exists(arg.credentials):
                        with open(arg.credentials, 'r') as file:
                            content = file.read().split("\n")
                            key = conv.hex_bytes(content[0]) ; iv = conv.hex_bytes(content[1])
                            if os.path.exists(arg.path_or_data_enc):
                                with open(arg.path_or_data_enc) as f:
                                    ciphertext = f.read()
                                    ciphertext = conv.hex_bytes(ciphertext)
                                    plaintext = aes.decrypt(ciphertext, key, iv)
                                    print(f"Plaintext: {conv.bytes_str(plaintext)}")
                            else:
                                ciphertext = conv.hex_bytes(arg.path_or_data_enc)
                                plaintext = aes.decrypt(ciphertext, key, iv)
                                print(f"Plaintext: {conv.bytes_str(plaintext)}")
                    else:
                        print("Path not exist!")
                else:
                    print("You must use --credential option for specifying the key & iv path")
        
        # Secure Hash module         
        elif arg.command == "secure_hash":
            
            secure_hash = SecureHash(conv)
            hash_type = arg.hash_type
            chunck_size = 8192 # specify the chunck size (in byte) for reading files
            hash_value = ""
            flag = False # if flag=T it is a path to read file 
            
            if os.path.exists(arg.path_or_data_hash):
                flag = True 
                hash_value = secure_hash.cal_hash(arg.path_or_data_hash, hash_type, flag, chunck_size)
                hash_value = conv.bytes_hex(hash_value)
                print(f"Hash Value: {hash_value}")
            else:
                flag = False
                # print(f"Data: {arg.path_or_data_hash}, type: {type(arg.path_or_data_hash)}")
                plaintext = conv.str_bytes(arg.path_or_data_hash)
                hash_value = secure_hash.cal_hash(plaintext, hash_type, flag, chunck_size)
                hash_value = conv.bytes_hex(hash_value)
                print(f"Hash Value: {hash_value}")

            if arg.compare:
                if arg.compare == hash_value:
                    print("[+] Hashes are the same")
                else:
                    print("[-] `hashes are not the same!")
        
        
# # Assymetric Cryptography
# class RSA:
#     def __init__(self):
#         pass


if __name__ == '__main__':
    command = CommandHandler()
    command.main()



"""
aes usage example: 
    
    -- encryption 
    python .\cryptography-tools.py aes 
    encrypt "D:\Eternal_Liberty_And_Glory\Source Codes\Cryptography\Cryptography-Utils\src\Statement.txt"
    
    -- decryption
    python .\cryptography-tools.py aes 
    decrypt "D:\Eternal_Liberty_And_Glory\Source Codes\Cryptography\Cryptography-Utils\src\Statement_enc.txt" 
    --credentials "D:\Eternal_Liberty_And_Glory\Source Codes\Cryptography\Cryptography-Utils\src\key 2024-05-18 16-42-04"


secure_hash usage example: 
    -- SHA256
    python .\cryptography-tools.py secure_hash SHA256 "HelloWorld!"
    -- SHA512
    python .\cryptography-tools.py secure_hash SHA512 "HelloWorld!"
"""