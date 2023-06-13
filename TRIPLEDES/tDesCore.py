from core import _Core
class _TripleDES(_Core):

    def tEncryptECB(self, data, keys):
        """ Triple self Encryption in ECB mode. """
        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        result = []
        subkeys = self._triple_generate_subkeys(keys)
        ct = None
        for pt_block in self._nsplit(pt, 64):
            ct = self._encrypt_block(pt_block, subkeys[0])  # encrypt each block
            ct = self._encrypt_block(ct, subkeys[1])
            ct = self._encrypt_block(ct, subkeys[2])
            result += ct
        result = self._bit_array_to_bytes(result)
        return result
    
    def tDecryptECB(self, data, key):
        """
        Triple DES Decryption in ECB mode.
        """
        pt = data
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        result = []
        ct = None
        # generate subkeys
        subkeys = self._triple_generate_subkeys(key, Decrypt=True)
        ct = None
        for pt_block in self._nsplit(pt, 64):
            ct = self._encrypt_block(pt_block, subkeys[2])  # encrypt each block
            ct = self._encrypt_block(ct, subkeys[1])
            ct = self._encrypt_block(ct, subkeys[0])
            result += ct
        result = self._bit_array_to_bytes(result)
        result = self._rem_padding(result)
        return result
    
    def tEncryptCBC(self, data, key, iv):
        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        result = []
        ct = None
        subkeys = self._triple_generate_subkeys(key)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for pt_block in self._nsplit(pt, 64):
            # XOR the IV with the plaintext block
            block = self._xor(pt_block, iv)
            ct = self._encrypt_block(block, subkeys[0])  # encrypt each block
            ct = self._encrypt_block(ct, subkeys[1])
            ct = self._encrypt_block(ct, subkeys[2])
            # Set the IV to the ciphertext block
            iv = ct
            result += ct
        result = self._bit_array_to_bytes(result)
        return result
    
    def tDecryptCBC(self, data, key, iv):
        pt = self._bytes_to_bit_array(data)  # convert to bit array
        result = []
        ct = []
        subkeys = self._triple_generate_subkeys(key, Decrypt=True) # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array

        for block in self._nsplit(pt, 64):
            # Decrypt the block
            ct = self._encrypt_block(block, subkeys[2])
            ct = self._encrypt_block(ct, subkeys[1])
            ct = self._encrypt_block(ct, subkeys[0])
            ct = self._xor(ct, iv)  # XOR the IV with the ciphertext block
            iv = block
            result += ct

        result = self._bit_array_to_bytes(result)
        result = self._rem_padding(result)
        return result
    
    def tEncryptOFB(self, data, key, iv):
        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        result = []
        subkeys = self._triple_generate_subkeys(key, Decrypt=False)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # Encrypt the IV
            iv = self._encrypt_block(iv, subkeys[0])
            iv = self._encrypt_block(iv, subkeys[1])
            iv = self._encrypt_block(iv, subkeys[2])
            # XOR the IV with the plaintext block
            result += self._xor(block, iv[:len(block)])
        result = self._bit_array_to_bytes(result)
        return result
    
    def tDecryptOFB(self, data, key, iv):
        pt = data
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        result = []
        subkeys = self._triple_generate_subkeys(key, Decrypt=False)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # Encrypt the IV
            iv = self._encrypt_block(iv, subkeys[0])
            iv = self._encrypt_block(iv, subkeys[1])
            iv = self._encrypt_block(iv, subkeys[2])
            # XOR the IV with the plaintext block
            result += self._xor(block, iv[:len(block)])
        result = self._bit_array_to_bytes(result)
        return result
