import typing

class Conversions:

    def str_bytes(self, string: str) -> bytes:       
        return string.encode()
    
    def bytes_str(self, byte:bytes) -> str:
        return byte.decode('utf-8')

    def bytes_hex(self, byte: bytes) -> str:
      return byte.hex()

    def integer_bytes(self, integer:int , length:int = 10) -> bytes:
        return integer.to_bytes(length, 'big')

