from desCore import _DES
from tDesCore import _TripleDES

class DES(_DES):
    """ Implements the original DES algorithm with a 64-bit key and three block
        modes: ECB, CBC, and OFB. """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object
            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes """
        self.key = key
        self.mode = mode
        self.originalIV = b'\x00' * 8
        if iv is None and mode != "ECB":
            self.IV = self.originalIV
        self.IV = iv

    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes """
        self.IV = self.originalIV

    def encrypt(self, data):
        """ Encrypts data with the DES encryption algorithm
            Parameters:
              data (bytes) - raw byte string to be encrypted """
        if self.mode == "ECB":
            encrypted = self.encryptECB(data, self.key)
        elif self.mode == "CBC":
            encrypted = self.encryptCBC(data, self.key, self.IV)
        elif self.mode == "OFB":
            encrypted = self.encryptOFB(data, self.key, self.IV)
        else:
            raise ValueError("Invalid mode: " + self.mode)
        return encrypted

    def decrypt(self, data):
        """ Decrypts data with the DES encryption algorithm.
            Parameters:
              data - raw byte string to be decrypted """
        if self.mode == "ECB":
            decrypted = self.decryptECB(data, self.key)
        elif self.mode == "CBC":
            decrypted = self.decryptCBC(data, self.key, self.IV)
        elif self.mode == "OFB":
            decrypted = self.decryptOFB(data, self.key, self.IV)
        else:
            raise ValueError("Invalid mode: " + self.mode)
        return decrypted


class TDES(_TripleDES):
    """ Implements the Triple DES algorithm with a 192-bit key and three block
        modes: ECB, CBC, and OFB. """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object.
            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes """
        self.key = key
        self.mode = mode
        self.originalIV = b'\x00' * 8
        if iv is None and mode != "ECB":
            self.IV = self.originalIV
        self.IV = iv
        self._split_encryption_keys()

    def _split_encryption_keys(self):
        """ Splits a Triple-DES encryption key into three 8-byte subkeys. Each
            subkey will be used for one of the DES rounds """
        key = self.key
        self.key = [key[:8], key[8:16], key[16:24]]
    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes """
        self.key = self.originalIV
        self._split_encryption_keys()

    def encrypt(self, data):
        """ Encrypts data with the Triple-DES encryption algorithm.
            Parameters:
              data - raw byte string to be encrypted """
        if self.mode == "ECB":
            encrypted = self.tEncryptECB(data, self.key)
        elif self.mode == "CBC":
            encrypted = self.tEncryptCBC(data, self.key, self.IV)
        elif self.mode == "OFB":
            encrypted = self.tEncryptOFB(data, self.key, self.IV)
        else:
            raise ValueError("Invalid mode: " + self.mode)
        return encrypted

    def decrypt(self, data):
        """ Decrypts data with the Triple-DES encryption algorithm.
            Parameters:
              data - raw byte string to be decrypted """
        if self.mode == "ECB":
            decrypted = self.tDecryptECB(data, self.key)
        elif self.mode == "CBC":
            decrypted = self.tDecryptCBC(data, self.key, self.IV)
        elif self.mode == "OFB":
            decrypted = self.tDecryptOFB(data, self.key, self.IV)
        else:
            raise ValueError("Invalid mode: " + self.mode)
        return decrypted