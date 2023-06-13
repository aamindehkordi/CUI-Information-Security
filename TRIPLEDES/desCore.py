from core import _Core
class _DES(_Core):

    def encryptECB(self, data, key):
        """ Encrypts plaintext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be encrypted
              key (bytes):  64-bit key used for DES encryption
    
            Returns:
              An encrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = self._generate_subkeys(key)  # generate subkeys
        for block in self._nsplit(pt, 64):
            ct += self._encrypt_block(block, subkeys)  # encrypt each block
        ct = self._bit_array_to_bytes(ct)
        return ct
    
    def decryptECB(self, data, key):
        """ Decrypts ciphertext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be decrypted
              key (bytes):  64-bit key used for DES decryption
    
            Returns:
              A decrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        pt = data  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = list(reversed(self._generate_subkeys(key)))  # generate subkeys
        for block in self._nsplit(pt, 64):
            ct += self._encrypt_block(block, subkeys)  # encrypt each block
        #ct = _rem_padding(ct)
        ct = self._bit_array_to_bytes(ct)
        ct = self._rem_padding(ct)
        return ct
    
    def encryptCBC(self, data, key, iv):
        """ Encrypts plaintext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be encrypted
              key (bytes):  64-bit key used for DES encryption
              iv (bytes):   64-bit initialization vector
    
            Returns:
              An encrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        if iv == None:
            raise ValueError("IV is None")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes long")
        if not self._isInstance(iv, bytes):
            raise TypeError("IV must be a bytestring")
        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = self._generate_subkeys(key)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # XOR the IV with the plaintext block
            block = self._xor(block, iv)
            # Encrypt the block
            ct += self._encrypt_block(block, subkeys)
            # Set the IV to the ciphertext block
            iv = ct[-64:]
        ct = self._bit_array_to_bytes(ct)
        return ct
    
    def decryptCBC(self, data, key, iv):
        """ Decrypts ciphertext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be decrypted
              key (bytes):  64-bit key used for DES decryption
              iv (bytes):   64-bit initialization vector
    
            Returns:
              A decrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        if iv == None:
            raise ValueError("IV is None")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes long")
        if not self._isInstance(iv, bytes):
            raise TypeError("IV must be a bytestring")
        pt = data# add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = list(reversed(self._generate_subkeys(key)))  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # Decrypt the block
            ct += self._encrypt_block(block, subkeys)
            # XOR the IV with the plaintext block
            ct[-64:] = self._xor(ct[-64:], iv)
            # Set the IV to the ciphertext block
            iv = block
        ct = self._bit_array_to_bytes(ct)
        ct = self._rem_padding(ct)
        return ct
    
    def encryptOFB(self, data, key, iv):
        """ Encrypts plaintext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be encrypted
              key (bytes):  64-bit key used for DES encryption
              iv (bytes):   64-bit initialization vector
    
            Returns:
              An encrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        if iv == None:
            raise ValueError("IV is None")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes long")
        if not self._isInstance(iv, bytes):
            raise TypeError("IV must be a bytestring")

        pt = self._add_padding(data)  # add padding
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = self._generate_subkeys(key)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # Encrypt the IV
            iv = self._encrypt_block(iv, subkeys)
            # XOR the IV with the plaintext block
            ct += self._xor(block, iv)
        ct = self._bit_array_to_bytes(ct)
        return ct
    
    def decryptOFB(self, data, key, iv):
        """ Decrypts ciphertext data with DES (Data Encryption Standard).
    
            Parameters:
              data (bytes): input data to be decrypted
              key (bytes):  64-bit key used for DES decryption
              iv (bytes):   64-bit initialization vector
    
            Returns:
              A decrypted byte string of equal length to the original data
        """
        if key == None:
            raise ValueError("Key is None")
        '''if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        '''
        if not self._isInstance(key, bytes):
            raise TypeError("Key must be a bytestring")
        if iv == None:
            raise ValueError("IV is None")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes long")
        if not self._isInstance(iv, bytes):
            raise TypeError("IV must be a bytestring")
        pt = data
        pt = self._bytes_to_bit_array(pt)  # convert to bit array
        ct = []
        subkeys = self._generate_subkeys(key)  # generate subkeys
        iv = self._bytes_to_bit_array(iv)  # convert IV to bit array
        for block in self._nsplit(pt, 64):
            # Encrypt the IV
            iv = self._encrypt_block(iv, subkeys)
            # XOR the IV with the ciphertext block
            ct += self._xor(block, iv)
        ct = self._bit_array_to_bytes(ct)

        return ct
    
    def _run_integration_tests(self, plaintext, key, mode='ECB', iv=None):
        """ Runs a set of integration tests to ensure that the DES implementation
            is working correctly. """
        # DES ECB encryption test
        if mode == "ECB":
            print('Testing DES encryption...')
            print('Plaintext: %s' % plaintext)
            print('Key: %s' % key)
            ciphertext = self.encryptECB(plaintext, key)
            print('Ciphertext: %s' % ciphertext)
            # DES decryption test
            print('Testing DES decryption...')
            decrypted = self.decryptECB(ciphertext, key)
            print('Decrypted: %s' % decrypted)
        if mode == "CBC":
            print('Testing DES encryption...')
            print('Plaintext: %s' % plaintext)
            print('Key: %s' % key)
            ciphertext = self.encryptCBC(plaintext, key, iv)
            print('Ciphertext: %s' % ciphertext)
            # DES decryption test
            print('Testing DES decryption...')
            decrypted = self.decryptCBC(ciphertext, key, iv)
            print('Decrypted: %s' % decrypted)
        if mode == "OFB":
            print('Testing DES encryption...')
            print('Plaintext: %s' % plaintext)
            print('Key: %s' % key)
            ciphertext = self.encryptOFB(plaintext, key, iv)
            print('Ciphertext: %s' % ciphertext)
            # DES decryption test
            print('Testing DES decryption...')
            decrypted = self.decryptOFB(ciphertext, key, iv)
            print('Decrypted: %s' % decrypted)