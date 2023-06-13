class _Core:
    def __init__(self):
        pass

    def _hex_print(self, block):
        """
            Prints a block of data in hexadecimal format.
        """
        for i, x in enumerate(block):
            if i % 4 == 0:
                print(' ', end='')
            print(x, end='')
        print()

    def _f_function(self, r, key):
        """ Performs the DES encryption "function" on the 32-bit Right Side of a
            64-bit block. This operation is invoked 16 times for each block, each
            time with a different subkey.
        """
    # Expand the 32-bit Right Side to 48-bits
        r = self._permute(r, self._EXPAND)
        # XOR the 48-bit result with the subkey
        r = self._xor(r, key)
        # Perform the S-BOX substitution
        r = self._substitute(r)
        # Permute the 32-bit result
        r = self._permute(r, self._CONTRACT)
        # Return the 32-bit result
        return r

    def _substitute(self, bit_array):
        """ Performs a DES S-BOX substitution for a 48-bit block. The input data
            should be a list of 0/1 integer values. Output will be a 32-bit block
            that is also a list of 0/1 integer values. Technically, the function
            can be used with smaller inputs as long as the length is a multiple of
            six. Smaller inputs will ignore some of the S-BOX tables.
            For example:
              _substitute([1,1,1,1,1,1,0,0,0,0,0,0]) => [1,1,0,1,1,1,1,1]
              _substitute([0,1,0,1,0,1,0,0,1,0,1,1]) => [1,1,0,0,0,0,1,0]
              _substitute([1,1,0,1,1,1,1,1,1,0,1,1]) => [1,1,1,0,0,1,0,1]
        """
        result = []
        for i, chunk in enumerate(self._nsplit(bit_array, 6)):
            # Get the row and column indices
            row = int(str(chunk[0]) + str(chunk[5]), 2)
            col = int(''.join(str(bin) for bin in chunk[1:5]), 2)
            # Get the value from the S-BOX table
            val = self._S_BOXES[i][row][col]
            # Convert the value to binary
            sval = bin(val)[2:].zfill(4)
            # Add the binary value to the result
            result += [int(x) for x in sval]

        return result

    def _triple_generate_subkeys(self, keys, Decrypt=False):
        """
            Generates 16 DES subkeys from a 64-bit encryption key.
            The encryption key should be given as a bytes string.
            Output is a 16-element list of bit arrays, where each
            array is a list of 48 ones/zeroes.
        """
        subkeys = []
        if Decrypt==False:
            subkeys.append(self._generate_subkeys(keys[0]))
            subkeys.append(list(reversed(self._generate_subkeys(keys[1]))))
            subkeys.append(self._generate_subkeys(keys[2]))
        if Decrypt:
            subkeys.append(list(reversed(self._generate_subkeys(keys[0]))))
            subkeys.append(self._generate_subkeys(keys[1]))
            subkeys.append(list(reversed(self._generate_subkeys(keys[2]))))
        return subkeys

    def _generate_subkeys(self, encryption_key):
        """ Generates 16 DES subkeys from a 64-bit encryption key. The encryption
            key should be given as a bytes string. Output is a 16-element list of
            bit arrays, where each array is a list of 48 ones/zeroes.
       """
        #check if key is int and fix it
        if type(encryption_key) == int:
            encryption_key = encryption_key.to_bytes(8, byteorder='big')
        subkeys = []
        # Convert the encryption key to a bit array
        keybits = self._bytes_to_bit_array(encryption_key)
        # Permute the key bits using the PC-1 table
        initialPerm = self._permute(keybits, self._KEY_PERMUTATION1)
        # Split the permuted key into left and right halves
        rightWing = initialPerm[:28]
        leftWing = initialPerm[28:]
        for i in range(16):
            # Rotate the left and right halves of the key
            leftWing = self._lshift(leftWing, self._KEY_SHIFT[i])
            rightWing = self._lshift(rightWing, self._KEY_SHIFT[i])
            # Combine the left and right halves of the key
            combinedWing = rightWing + leftWing
            subkeys.append(self._permute(combinedWing, self._KEY_PERMUTATION2))
        return subkeys


    def _add_padding(self, message):
        """
            Adds padding to the end of a byte string to make its length a multiple
            of eight. The value of each byte of padding is equal to the number of
            bytes being added to the byte string.
        """
        # Determine the number of bytes to add
        num_bytes_to_add = 8 - (len(message) % 8)
        # Add the bytes to the message
        message += bytes([num_bytes_to_add]) * num_bytes_to_add
        # Return the message with the padding
        return message


    def _rem_padding(self, message):
        """
            Removes the padding off the end of a byte string where the last byte
            specifies the number of bytes to remove.
        """
        # Determine the number of bytes to remove
        num_bytes_to_remove = message[-1]
        # Return the message without the padding
        return message[:-num_bytes_to_remove]


    def _bit_array_to_bytes(self, bit_array):
        """ Converts an array of bits (list of integers 0/1) into a byte string. """
        result = []
        byte = 0
        for bit in range(len(bit_array)):
            byte += bit_array[bit] << (7 - (bit % 8))
            if (bit % 8) == 7:
                result += [byte]
                byte = 0
        if byte != 0:
            result += [byte]
        return bytes(result)


    def _bytes_to_bit_array(self, byte_string):
        """ Converts a byte string into an array of bits (list of integers 0/1). """
        result = []
        for byte in byte_string:
            for bit in [7, 6, 5, 4, 3, 2, 1, 0]:  # takes each byte in byte string
                mask = 1 << bit  # checks the byte and mask
                if byte & mask > 0:  # if both are greater than 0 return 1
                    result.append(1)
                else:
                    result.append(0)
        return result


    def _nsplit(self, data, split_size=64):
        """
            Divides the data into blocks that are 'split_size' in length, yielding
            one block at a time. If the data is not evenly divisible by the split
            size then the last block will be smaller than all the others.
        """
        # For each block of data
        for i in range(0, len(data), split_size):
            # Yield the block of data
            yield data[i:i + split_size]


    def _lshift(self, sequence, n):
        """
            Left shifts sequence of bytes by the specified number. All elements
            that fall off the left side are rotated back around to the right side.
        """
        # Left shift the sequence
        sequence = sequence[n:] + sequence[:n]
        # Return the left shifted sequence
        return sequence


    def _xor(self, x, y):
        """
            Bitwise XOR of two iterable variables. If the iterables are different
            lengths, then the function will only compute XOR over the parallel
            portion of the two sequences.
            For example:
              _xor([0,0,1,1], [0,1,0,1])       => [0,1,1,0]
              _xor([0,0,1,1], [0,1])           => [0,1]
              _xor([1,2,3,4], [1,2,3,0])       => [0,0,0,4]
              _xor([0x0F0F], [0x55AA])         => [0x5AA5]
              _xor([0x0F, 0x0F], [0x55, 0xAA]) => [0x5A, 0xA5]
              _xor(b"\x0F\x0F", b"\x55\xAA")   => [0x5A, 0xA5]
              _xor(0x0F0F, 0x55AA)             => TypeError: not iterable
        """
        bitwise_array = []
        x_len = len(x)
        y_len = len(y)
        xor_length = min(x_len, y_len)
        longer = x if (x_len > y_len) else y

        for i in range(xor_length):
            xor = x[i] ^ y[i]
            bitwise_array.append(xor)

        if x_len != y_len:
            bitwise_array += longer[xor_length:]

        return bitwise_array

    def _permute(self, block, table):
        """
            Permutes the given block of data using the given table.
        """
        new_block = []
        for i in table:
            new_block.append(block[i])
        return new_block

    def _isInstance(self, key, bytes):
        if type(key) == bytes:
            return True
        else:
            return False

    def _encrypt_block(self, block, subkeys):
        """ Encrypts a single 64-bit block with the DES algorithm. The input is a
            64 element array of 0/1 integers and a list of 16 subkeys, themselves
            each a 48 element array of 0/1 integers.
        """
        # Initial permutation
        block = self._permute(block, self.INIT_PERMUTATION)

        # Perform 16 rounds of DES
        for i in range(16):
            # Split the block into two 32-bit halves
            leftWing = block[:32]
            rightWing = block[32:]
            # Save the current left wing
            temp = leftWing
            # Left wing is the current right wing
            leftWing = rightWing
            # Right wing is the current left wing
            fOut = self._f_function(rightWing, subkeys[i])
            # XOR the F function output with the original left wing
            leftWing = self._xor(temp, fOut)
            # Combine the two 32-bit halves
            block = rightWing + leftWing
        # Final permutation
        block = block[32:] + block[:32]
        block = self._permute(block, self.FINAL_PERMUTATION)
        # _hex_print(block)
        # Return the encrypted block
        return block


    # 32-bit to 48-bit
    _EXPAND = [31,  0,  1,  2,  3,  4,  3,  4,
                5,  6,  7,  8,  7,  8,  9, 10,
               11, 12, 11, 12, 13, 14, 15, 16,
               15, 16, 17, 18, 19, 20, 19, 20,
               21, 22, 23, 24, 23, 24, 25, 26,
               27, 28, 27, 28, 29, 30, 31,  0]

    # 32-bit permutation after S-BOX substitution
    _CONTRACT = [15,  6, 19, 20, 28, 11, 27, 16,
                  0, 14, 22, 25,  4, 17, 30,  9,
                  1,  7, 23, 13, 31, 26,  2,  8,
                 18, 12, 29,  5, 21, 10,  3, 24]

    # Initial permutation on incoming block
    INIT_PERMUTATION = [57, 49, 41, 33, 25, 17, 9, 1,
                        59, 51, 43, 35, 27, 19, 11, 3,
                        61, 53, 45, 37, 29, 21, 13, 5,
                        63, 55, 47, 39, 31, 23, 15, 7,
                        56, 48, 40, 32, 24, 16, 8, 0,
                        58, 50, 42, 34, 26, 18, 10, 2,
                        60, 52, 44, 36, 28, 20, 12, 4,
                        62, 54, 46, 38, 30, 22, 14, 6]

    # Inverse of _INITIAL_PERMUTATION
    FINAL_PERMUTATION = [39, 7, 47, 15, 55, 23, 63, 31,
                         38, 6, 46, 14, 54, 22, 62, 30,
                         37, 5, 45, 13, 53, 21, 61, 29,
                         36, 4, 44, 12, 52, 20, 60, 28,
                         35, 3, 43, 11, 51, 19, 59, 27,
                         34, 2, 42, 10, 50, 18, 58, 26,
                         33, 1, 41, 9, 49, 17, 57, 25,
                         32, 0, 40, 8, 48, 16, 56, 24]

    _S_BOXES = [
        [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
         [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
         [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
         [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
        ],
        [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
         [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
         [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
         [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
        ],
        [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
         [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
         [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
         [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
        ],
        [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
         [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
         [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
         [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
        ],
        [[ 2, 12,  4,  1,  7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11,  2, 12,  4,  7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [ 4,  2,  1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11,  8, 12,  7,  1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
         [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
         [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
         [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
        ],
        [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
         [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
         [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
         [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
        ],
        [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
         [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
         [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
         [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
        ]
    ]
    # 64-bit to 56-bit permutation on the key
    _KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16,  8,  0,
                         57, 49, 41, 33, 25, 17,  9,  1,
                         58, 50, 42, 34, 26, 18, 10,  2,
                         59, 51, 43, 35, 62, 54, 46, 38,
                         30, 22, 14,  6, 61, 53, 45, 37,
                         29, 21, 13,  5, 60, 52, 44, 36,
                         28, 20, 12,  4, 27, 19, 11,  3]

    # 56-bit to 48-bit permutation on the key
    _KEY_PERMUTATION2 = [13, 16, 10, 23,  0,  4,  2, 27,
                         14,  5, 20,  9, 22, 18, 11,  3,
                         25,  7, 15,  6, 26, 19, 12,  1,
                         40, 51, 30, 36, 46, 54, 29, 39,
                         50, 44, 32, 47, 43, 48, 38, 55,
                         33, 52, 45, 41, 49, 35, 28, 31]

    _KEY_SHIFT = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def _run_unit_tests(self):
        """
                Runs unit tests for each function in this module. Prints 'ALL UNIT
                TESTS PASSED' if all the unit tests were successful. Raises an
                AssertionError if a unit test fails.
            """
        # Test _add_padding
        assert self._add_padding(b'abc') == b'abc\x05\x05\x05\x05\x05'

        # Test _rem_padding
        assert self._rem_padding(b'abc\x05\x05\x05\x05\x05') == b'abc'

        # Test _bytes_to_bit_array
        assert self._bytes_to_bit_array(b'abc') == [0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1]

        # Test _bit_array_to_bytes
        assert self._bit_array_to_bytes([0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1]) == b'abc'

        # Test _nsplit
        assert list(self._nsplit(b'abcdefghijklmnopqrstuvwxyz', 8)) == [b'abcdefgh', b'ijklmnop', b'qrstuvwx', b'yz']

        # Test _lshift
        assert self._lshift([0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1], 1) == [1, 1, 0, 0, 0, 0, 1,
                                                                                                             0, 1, 1, 0, 0, 0, 1,
                                                                                                             0, 0, 1, 1, 0, 0, 0,
                                                                                                             1, 1, 0]

        # Test _xor
        assert self._xor([0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1],
                         [1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0]) == [1, 0, 1, 0, 0, 0, 1, 1, 1,
                                                                                                  0, 1, 0, 0, 1, 1, 0, 1, 0,
                                                                                                  1, 0, 0, 1, 0, 1]

        # Test _permute
        assert self._permute([0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1],
                             [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]) == [0, 1, 1,
                                                                                                                    0, 0, 0,
                                                                                                                    0, 1, 0,
                                                                                                                    1, 1, 0,
                                                                                                                    0, 0, 1,
                                                                                                                    0, 0, 1,
                                                                                                                    1, 0, 0,
                                                                                                                    0, 1, 1]

        subkey_input = b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80"
        subkey_result = [[0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
                          1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                         [1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
                          0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1],
                         [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
                          0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1],
                         [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1],
                         [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1],
                         [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1],
                         [1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
                         [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
                         [1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0,
                          0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                         [1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0,
                          1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                         [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0,
                          1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                         [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0,
                          1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                         [0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0,
                          1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                         [0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0,
                          1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                         [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1,
                          1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                         [1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                          0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1]]
        assert self._generate_subkeys(subkey_input) == subkey_result
        print('ALL UNIT TESTS PASSED')