# symmertic imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# asymmetric imports 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
# hash imports
from cryptography.hazmat.primitives import hashes
# backend imports 
from cryptography.hazmat.backends import default_backend
# others 
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
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) 
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
    
    def encrypt(self, plaintext, credentials_path):
        (key,  iv)= self.generate_key_iv()
        cipher = self.craft_AES_cipher(key, iv)
        encryptor = cipher.encryptor()
        # plaintext = b"Secret Messaage must be transmitted securely to the remote"
        padded_plaintext = self.padding(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        self.store_key(key, iv, credentials_path)
        self.store_ciphertext(ciphertext)
        return (ciphertext, key, iv)

    def decrypt(self, ciphertext, key, iv):
        cipher = self.craft_AES_cipher(key, iv)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self.unpadding(padded_plaintext)
        return plaintext

    def path_creator(self, forWhat):
        cwd = os.getcwd()
        full_time = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        path = cwd + f"\\{forWhat} " + full_time
        return path
    
    def store_key(self, key, iv, credentials_path):
        path = ""
        if credentials_path:
            path = credentials_path    
        else:
            path = self.path_creator("key")
        
        key  = self.conv.bytes_hex(key); iv = self.conv.bytes_hex(iv)
        try:
            with open(path, "w") as file:
                file.write(key); file.write("\n") ; file.write(iv)
                return path
        except FileNotFoundError as e:
            print(e)
    
    def store_ciphertext(self, ciphertext):
        
        path = self.path_creator("ciphertext")
        try:
            with open(path, 'wb') as file: 
                file.write(ciphertext)
        except FileNotFoundError as e:
            print(e)

class SecureHash:
    def __init__(self, conv):
        self.conv = conv
        
    def select_hash_func(self, hash_type):
        
        digest: hashes.Hash
        
        if hash_type == "MD5":
            digest = hashes.Hash(hashes.MD5(),backend=default_backend())
        elif hash_type == "SHA1":
            digest = hashes.Hash(hashes.SHA1(),backend=default_backend())
        elif hash_type == "SHA384":
            digest = hashes.Hash(hashes.SHA384(),backend=default_backend())
        elif hash_type == "SHA512":
            digest = hashes.Hash(hashes.SHA512(),backend=default_backend())
        elif hash_type == "SHA3_256":
            digest = hashes.Hash(hashes.SHA3_256(),backend=default_backend())
        elif hash_type == "SHA3_384":
            digest = hashes.Hash(hashes.SHA3_384(),backend=default_backend())
        elif hash_type == "SHA3_512":
            digest = hashes.Hash(hashes.SHA3_512(),backend=default_backend())
        else:
            digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
            
        return digest
    
    def cal_hash(self, path_or_data, hash_type, flag, chunck_size=8192):
        if flag: #file eixst and read content from file 
            digest = self.select_hash_func(hash_type)
            with open(path_or_data, 'rb') as file:
                while chunck := file.read(chunck_size):
                    digest.update(chunck)

            hash_value = digest.finalize()
            return hash_value
        else: #file not eixst and read content from commandline buffer
            digest = self.select_hash_func(hash_type)
            digest.update(path_or_data)
            hash_value = digest.finalize()
            return hash_value

    def compare(self, calculated_hash, official_hash):
        if calculated_hash == official_hash:
            print("[+] Hashes are the same")
        else:
            print("[-] Hashes are not the same!")

# Assymetric Cryptography
class RSA:
    def __init__(self, conv):
        self.conv = conv
        
    def key_generation(self, ):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return (private_key, public_key)
    
    def key_serialization(self, private_key, public_key):
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return (pem_private_key, pem_public_key)
        """
        format=serialization.PrivateFormat: 
            PKCS8: Specifies the format for private key storage (PKCS8 is a standard format).

format=serialization.PublicFormat.SubjectPublicKeyInfo: Specifies the format for public key storage (SubjectPublicKeyInfo is a standard format).    
        """
        
    def encrypt(self, plaintext):
        private_key, public_key = self.key_generation()
        
        ciphertext = public_key.encrypt(plaintext, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        print(f"Ciphertext: {self.conv.bytes_hex(ciphertext)}")
        print(f"Public key: {public_key}\nPrivate key: {private_key}")
        return ciphertext
    
    def decrypt(self, ciphertext, private_key):
        private_key.decrypt(
            ciphertext, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        
    
    

class CommandHandler:
    def AES_handler(self, subparsers):
        AES_parser = subparsers.add_parser("aes", description="AES256-CBC mode", help="AES encryption algorithm.")
        AES_parser.add_argument("cipher_or_decipher", type=str, choices=["encrypt", "decrypt"], help="Choose between encryption/decryption.")
        AES_parser.add_argument("path_or_data_enc", type=str, help="Plaintext value/File address")
        AES_parser.add_argument("credentials", nargs="?", default=None, type=str, help="Credentials (key, iv) path")
        
    def secure_hash_handler(self, subparsers):
        secure_hash_parser = subparsers.add_parser("secure_hash", description="Using different Hash function for getting message digest", help="Secure Hash functions")
        secure_hash_parser.add_argument("hash_type", type=str, choices=["MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512"])
        secure_hash_parser.add_argument("path_or_data_hash", type=str, help="Plaintext value/File address")
        secure_hash_parser.add_argument("--compare", type=str, help="Compare calculated hash with official published hash")
        
    def RSA_handler(self, subparsers):
        RSA_parser = subparsers.add_parser("rsa", description="RSA-OAEP-MGF1-SHA256", help="RSA encryption")
        RSA_parser.add_argument("cipher_or_decipher", type=str, choices=["encryption", "decryption"])
        RSA_parser.add_argument("path_or_data_enc", type=str, help="Plaintext value/File adress")
        RSA_parser.add_argument("credentials",  nargs="?", default=None, type=str, help="Credentials (key) path")
    
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

        self.AES_handler(subparsers)
        self.secure_hash_handler(subparsers)
        # self.RSA_handler(subparsers)
        
        arg = parser.parse_args()
        
        conv = Conversions()
        
        # AES module
        if arg.command == "aes":
            aes = AES(conv)
            if arg.cipher_or_decipher == "encrypt":
                if os.path.exists(arg.path_or_data_enc):
                    with open(arg.path_or_data_enc, 'rb') as file:
                        plaintext = file.read()
                        ciphertext, key, iv = aes.encrypt(plaintext, arg.credentials)
                        print(f"ciphertext: {conv.bytes_hex(ciphertext)}")
                else:
                    plaintext = conv.str_bytes(arg.path_or_data_enc)
                    ciphertext, key, iv = aes.encrypt(plaintext, arg.credentials)
                    print(f"ciphertext: {conv.bytes_hex(ciphertext)}")
            else:
                # decryption
                # D:\Eternal_Liberty_And_Glory\Source Codes\Cryptography\Cryptography-Utils\src\key 2024-05-17 22-36-16
                if os.path.exists(arg.path_or_data_enc):
                    with open(arg.path_or_data_enc, 'rb') as file:
                        ciphertext = file.read()
                        if os.path.exists(arg.credentials):
                            with open(arg.credentials, 'r') as f:
                                content = f.read().split("\n")
                                key = conv.hex_bytes(content[0]) ; iv = conv.hex_bytes(content[1])
                                plaintext = aes.decrypt(ciphertext, key, iv)
                                print(f"Plaintext: {conv.bytes_str(plaintext)}")
                        else:
                            print("Credential path not exist!")
                else:
                    if os.path.exists(arg.credentials):
                        with open(arg.credentials, 'r') as file:
                            content = file.read().split("\n")
                            key = conv.hex_bytes(content[0]) ; iv = conv.hex_bytes(content[1])
                            ciphertext = conv.hex_bytes(arg.path_or_data_enc)
                            plaintext = aes.decrypt(ciphertext, key, iv)
                            print(f"Plaintext: {conv.bytes_str(plaintext)}")
                    else:
                        print("Credential path not exist!")
                
            
                    

        
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
                secure_hash.compare(hash_value, arg.compare)
                    
        
        elif arg.command == "rsa":
            if os.path.exists(arg.path_or_data_enc):
                with open(arg.path_or_data_enc) as file:
                    pass
                #TDOO 
            else:
                pass



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
    -- MD5 txt file
    python .\cryptography-tools.py secure_hash MD5 ".\Statement.txt" --compare "340fadfbb978e5e3a1c11359c92d83c7"
    -- MD5 ISO file
    python .\cryptography-tools.py secure_hash MD5 "F:\DOWNLOADS\CSI_Linux_2023.2_VMware.7z" --compare "45ffb4ac025b31b831146a09f7d3ddd0"
"""