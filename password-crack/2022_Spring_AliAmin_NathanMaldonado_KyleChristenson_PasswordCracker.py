"""
The LM hash is computed as follows:[1][2]
    1. The user's password is restricted to a maximum of fourteen characters.
    2. The user’s password is converted to uppercase
    3. The user's password is encoded in the System OEM code page
    4. This password is NULL-padded to 14 bytes.
    5. The “fixed-length” password is split into two 7-byte halves.
    6. These values are used to create two DES keys, one from each 7-byte half, by converting the seven bytes into a bit
stream with the most significant bit first, and inserting a paritybit after every seven bits (so 1010100 becomes
10101000). This generates the 64 bits needed for a DES key. (A DES key ostensibly consists of 64 bits; however, only 56
of these are actually used by the algorithm. The parity bits added in this step are later discarded.)
    7. Each of the two keys is used to DES-encrypt the constant ASCII string
“KGS!@#$%”,[Notes 2] resulting in two 8-byte ciphertext values. The DES CipherMode should be set to ECB, and PaddingMode
should be set to NONE.
    8. These two ciphertext values are concatenated to form a 16-byte value, which is the LM hash.

If the password is 7 characters or less, then the second half of hash will always produce same constant value (
0xAAD3B435B51404EE). Therefore, a password is less than or equal to 7 characters long can be identified visibly
without using tools (though with high speed GPU attacks, this matters less).


Roadmap for the main() function:
    1. Start the timer
    2. Load the password dump file
    3. Load the password cracking dictionary
    4. For each password in the password dump file:
        a. For each word in the password cracking dictionary:
            i. Calculate the LM hash of the word
            ii. If the LM hash of the word matches the LM hash of the password in the password dump file:
                1. Print the username and password
                2. Stop the timer
                3. Print the time it took to crack the password
                4. Exit the program
    5. If the program has not exited yet, print a message that the password was not found
    6. Stop the timer
    7. Print the time it took to fail to crack the password
"""
# STANDARD IMPORTS
import time
import sys


# __________________________________Kyle's DES______________________________________________
class Core:
    _S_BOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
         ],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
         ],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
         ],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
         ],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
         ],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
         ],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
         ],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    # Expainsion table for expanding 32-bit right side to 48-bits
    _EXPAND = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
               11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
               21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

    _INIT_PERM = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
                  56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
                  60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6]

    _FINAL_PERM = [39, 7, 47, 15, 55, 23, 63, 31,
                   38, 6, 46, 14, 54, 22, 62, 30,
                   37, 5, 45, 13, 53, 21, 61, 29,
                   36, 4, 44, 12, 52, 20, 60, 28,
                   35, 3, 43, 11, 51, 19, 59, 27,
                   34, 2, 42, 10, 50, 18, 58, 26,
                   33, 1, 41, 9, 49, 17, 57, 25,
                   32, 0, 40, 8, 48, 16, 56, 24]

    _END_PERMUTATION = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
                        1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]
    # 64-bit to 56-bit permutation on the key
    _KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16, 8, 0,
                         57, 49, 41, 33, 25, 17, 9, 1,
                         58, 50, 42, 34, 26, 18, 10, 2,
                         59, 51, 43, 35, 62, 54, 46, 38,
                         30, 22, 14, 6, 61, 53, 45, 37,
                         29, 21, 13, 5, 60, 52, 44, 36,
                         28, 20, 12, 4, 27, 19, 11, 3]

    # 56-bit to 48-bit permutation on the key
    _KEY_PERMUTATION2 = [13, 16, 10, 23, 0, 4, 2, 27,
                         14, 5, 20, 9, 22, 18, 11, 3,
                         25, 7, 15, 6, 26, 19, 12, 1,
                         40, 51, 30, 36, 46, 54, 29, 39,
                         50, 44, 32, 47, 43, 48, 38, 55,
                         33, 52, 45, 41, 49, 35, 28, 31]

    # Matrix that determines the shift for each round of keys
    _KEY_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self):
        pass

    def _add_padding(self, message):
        """
            Adds padding to the end of a byte string to make its length a multiple
            of eight. The value of each byte of padding is equal to the number of
            bytes being added to the byte string.
        """
        if len(message) % 8 == 0:
            return message

        num_bytes_to_add = 8 - (len(message) % 8)
        padding = chr(num_bytes_to_add) * num_bytes_to_add

        return message + padding.encode("utf-8")

    def _rem_padding(self, message):
        """
            Removes the padding off the end of a byte string where the last byte
            specifies the number of bytes to remove.
        """
        num_bytes_to_remove = message[-1]

        return message[:-num_bytes_to_remove]

    def _bytes_to_bit_array(self, byte_string):
        """ Converts a byte string into an array of bits (list of integers 0/1). """
        result = []
        for byte in byte_string:
            for bit in [7, 6, 5, 4, 3, 2, 1, 0]:
                mask = 1 << bit
                if byte & mask > 0:
                    result.append(1)
                else:
                    result.append(0)

        return result

    def _bit_array_to_bytes(self, bit_array):
        """ Converts an array of bits (list of integers 0/1) into a byte string. """
        result = []
        byte = 0

        for i, bit in enumerate(bit_array):
            byte += bit << (7 - (i % 8))
            if (i % 8) == 7:
                result += [byte]
                byte = 0

        if byte != 0:
            result += [byte]

        return bytes(result)

    def _nsplit(self, data, split_size=64):
        """
            Divides the data into blocks that are 'split_size' in length, yielding
            one block at a time. If the data is not evenly divisible by the split
            size then the last block will be smaller than all the others.
        """
        for i in range(0, len(data), split_size):
            yield data[i:i + split_size]

    def _lshift(self, sequence, n):
        """ Left shifts sequence of bytes by the specified number. All elements
            that fall off the left side are rotated back around to the right side.
        """
        sequence = sequence[n:] + sequence[:n]

        return sequence

    def _xor(self, x, y):
        """ Bitwise XOR of two iterable variables. If the iterables are different
            lengths, then the function will only compute XOR over the parallel
            portion of the two sequences.
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

    def _substitute(self, data):
        """
        Uses SBOXES to substitute 6 bit chunks into 4 bit values. Takes an input 48 bits long and returns an output 32 bits long.
        """
        result = []
        for i, chunk in enumerate(self._nsplit(data, 6)):
            # Get the binary number from the first and last binaries of the chunk
            # Get the binary number from inside the chunk
            row = int(str(chunk[0]) + str(chunk[5]), 2)
            col = int(''.join(str(bin) for bin in chunk[1:5]), 2)
            val = self._S_BOXES[i][row][col]
            sval = bin(val)[2:].zfill(4)
            result += [int(x) for x in sval]

        return result

    def _permute(self, key_bits, permutation_table):
        """Transposes a block of data according to the specified permutation
            table, which is simply an n-element array that specifies the index
            of each element from the source array.
        """
        new_key = []
        for position in permutation_table:
            new_key.append(key_bits[position])

        return new_key

    def _generate_subkeys(self, encryption_key, shift_matrix, key_perm1, key_perm2):
        """ Generates 16 DES subkeys from a 64-bit encryption key. The encryption
            key should be given as a bytes string. Output is a 16-element list of
            bit arrays, where each array is a list of 48 ones/zeroes.
        """
        subkeys = []
        key_bits = self._bytes_to_bit_array(encryption_key)
        K_0 = self._permute(key_bits, key_perm1)

        right_side = K_0[:28]
        left_side = K_0[28:]

        for i in range(16):
            right_side = self._lshift(right_side, shift_matrix[i])
            left_side = self._lshift(left_side, shift_matrix[i])
            k_i = right_side + left_side
            subkeys.append(self._permute(k_i, key_perm2))

        return subkeys

    def _function(self, R, subkey):
        """ Performs the DES encryption "function" on the 32-bit Right Side of a
            64-bit block. This operation is invoked 16 times for each block, each
            time with a different subkey.
        """
        # Expansion
        final_R = self._permute(R, self._EXPAND)
        # XOR subkeys
        final_R = self._xor(final_R, subkey)
        # SBOX substitution
        final_R = self._substitute(final_R)
        # Last rightside permutation
        final_R = self._permute(final_R, self._END_PERMUTATION)

        return final_R

    def _encrypt_block(self, block, subkeys):
        """ Encrypts a single 64-bit block with the DES algorithm. The input is a
            64 element array of 0/1 integers and a list of 16 subkeys, themselves
            each a 48 element array of 0/1 integers.

            Parameters:
                block (bits): input data
        """
        block = self._permute(block, self._INIT_PERM)

        for i in range(16):
            left_side = block[:32]
            right_side = block[32:]

            new_right_side = self._function(right_side, subkeys[i])
            new_right_side = self._xor(new_right_side, left_side)

            block = right_side + new_right_side

        block = block[32:] + block[:32]
        block = self._permute(block, self._FINAL_PERM)
        return block

    def run_unit_tests(self):
        """
            Runs unit tests for each function in this module. Prints 'ALL UNIT
            TESTS PASSED' if all of the unit tests were successful. Raises an
            AssertionError if a unit test fails.
        """

        start = [1, "A", 14, "L", 8, "X", 6, ",", 2, 11, "S", "+", ";", "C", 7, 0,
                 "Z", 18, 4, 24, "P", 22, "D", "W", "/", 17, "J", "V", "M", "H", 13, 20,
                 "*", "=", "I", "T", 21, 6, "?", 25, 23, "Q", "U", "F", "%", 3, 15, "\\",
                 12, "E", 19, 16, 5, "N", "Y", 0, '"', "B", ".", "-", 9, ":", "R", "K"]

        expected = ['B', 'E', 'Q', '=', 17, 18, 11, 'A', '-', 16, 'F', 'T', 'V', 24, '+', 'L',
                    ':', 'N', 3, 6, 'H', 22, 'C', 'X', 'K', 0, '\\', 25, 20, 'W', 0, ',',
                    '"', 12, 23, '*', '/', 'Z', 2, 1, '.', 19, 'U', 'I', 'J', 4, 'S', 14,
                    9, 5, '%', 21, 'M', 'P', ';', 8, 'R', 'Y', 15, '?', 13, 'D', 7, 6]

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

        test1_result = self._add_padding(b'CSC428')
        test2_result = self._rem_padding(b'CSC428\x02\x02')
        test3_result = self._bytes_to_bit_array(b'abc')
        test4_result = self._bit_array_to_bytes(
            [0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1])
        test5_result = list(self._nsplit(b'abcdefghijklmnopqrstuvwxyz', 8))
        test6_result = self._lshift([1, 0, 1, 0, 1, 1, 1], 3)
        test7_result = self._xor([1, 1, 1, 1, 0], [1, 0, 0, 1, 0, 1, 1])
        test8_result = self._permute(start, self._INIT_PERM)
        test9_result = self._generate_subkeys(subkey_input, self._KEY_SHIFT, self._KEY_PERMUTATION1,
                                              self._KEY_PERMUTATION2)

        assert test1_result == b'CSC428\x02\x02', "Unit test #1 failed: _add_padding(b'CSC428')"

        assert test2_result == b'CSC428', "Unit test #2 failed: _rem_padding(b'CSC428\x02\x02')"

        assert test3_result == [0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1,
                                1], "Unit test #3 failed: _bytes_to_bit_array(b'abc')"

        assert test4_result == b'abc', "Unit test #4 failed: _bit_array_to_bytes([0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1])"

        assert test5_result == [b'abcdefgh', b'ijklmnop', b'qrstuvwx',
                                b'yz'], "Unit test #5 failed: list(_nsplit(b'abcdefghijklmnopqrstuvwxyz', 8))"

        assert test6_result == [0, 1, 1, 1, 1, 0, 1], "Unit test #6 failed: _lshift([1, 0, 1, 0, 1, 1, 1], 3)"

        assert test7_result == [0, 1, 1, 0, 0, 1, 1], "Unit test #7 failed: _xor([1,1,1,1,0], [1,0,0,1,0])"

        assert test8_result == expected, "Unit test #8 failed: _permute(start, _INIT_PERM)"

        assert test9_result == subkey_result, "Unit test #9 failed: _generate_subkeys(subkey_input)"

        print('ALL UNIT TESTS PASSED')


class DES(Core):
    """ Implements the original DES algorithm with a 64-bit key and three block
        modes: ECB, CBC, and OFB.
    """

    def __init__(self, key, mode="ecb", IV=b'\x00\x00\x00\x00\x00\x00\x00\x00', output_type="plaintext"):
        self.key = key
        self.mode = mode
        self.IV = IV
        self.output_type = output_type

    def encrypt(self, data):
        """ Encrypts plaintext data with DES (Data Encryption Standard).
            Modes: ECB CBC OFB
            Output_type: plaintext, hex
            Returns:
            An encrypted byte string of equal length to the original data
        """
        encrypted_bits = []
        mode = self.mode
        IV = self.IV
        key = self.key
        output_type = self.output_type

        if isinstance(data, str):
            data = data.encode('utf-8')

        if mode == 'ecb' or mode == 'cbc':
            padded_data = self._add_padding(data)
        else:
            IV = self._bytes_to_bit_array(IV)
            padded_data = data

        plain_as_bits = self._bytes_to_bit_array(padded_data)

        # Subkey Generation
        subkeys = self._generate_subkeys(key, self._KEY_SHIFT, self._KEY_PERMUTATION1, self._KEY_PERMUTATION2)

        # Split Plaintext into 64 bit blocks
        # run the core des function on each block
        # transform the encrypted block from 64bits back to a bytestring and add it to encrypted_bytestring
        for block in self._nsplit(plain_as_bits, 64):

            # CORE DES
            if mode == 'ecb':
                encrypted_block = self._encrypt_block(block, subkeys)
                encrypted_bits.extend(encrypted_block)

            elif mode == 'cbc':
                block = self._xor(IV, block)
                encrypted_block = self._encrypt_block(block, subkeys)
                encrypted_bits.extend(encrypted_block)
                IV = encrypted_block

            elif mode == 'ofb':
                encrypted_block = self._encrypt_block(IV, subkeys)
                IV = encrypted_block
                # Don't let _xor add more to the end of the encryptedblock when in ofb mode
                encrypted_block = self._xor(block, encrypted_block[:len(block)])
                encrypted_bits.extend(encrypted_block)

        final_bytes = self._bit_array_to_bytes(encrypted_bits)
        final_output = ''
        # Doing this to make ouput more similar to CyberChef's output
        if output_type == "plaintext":
            for byte in final_bytes:
                final_output += hex(byte)[2:].zfill(2)
        else:
            final_output = final_bytes

        return final_output

    def decrypt(self, data):
        """ Decrypts plaintext data with DES (Data Encryption Standard).

            Returns:
            A decrypted byte string of equal length to the original data
        """
        decrypted_bits = []

        string_to_byte = b''

        mode = self.mode
        IV = self.IV
        key = self.key
        output_type = self.output_type

        if isinstance(data, str):
            for i in range(0, len(data) - 1, 2):
                string_to_byte += bytes.fromhex(data[i:i + 2])

            data = string_to_byte

        IV = self._bytes_to_bit_array(IV)
        if mode == 'ecb' or mode == 'cbc':
            # Subkey Generation
            subkeys = list(
                reversed(self._generate_subkeys(key, self._KEY_SHIFT, self._KEY_PERMUTATION1, self._KEY_PERMUTATION2)))

        elif mode == 'ofb':
            # Subkey Generation
            subkeys = self._generate_subkeys(key, self._KEY_SHIFT, self._KEY_PERMUTATION1, self._KEY_PERMUTATION2)

        plain_as_bits = self._bytes_to_bit_array(data)

        # Split cyphertext into 64 bit blocks
        # run the core des function on each block
        # transform the encrypted block from 64bits back to a bytestring and add it to encrypted_bytestring
        for block in self._nsplit(plain_as_bits, 64):

            # CORE DES
            if mode == 'ecb':
                decrypted_block = self._encrypt_block(block, subkeys)
                decrypted_bits.extend(decrypted_block)

            elif mode == 'cbc':
                decrypted_block = self._encrypt_block(block, subkeys)
                decrypted_block = self._xor(decrypted_block, IV)
                decrypted_bits.extend(decrypted_block)
                IV = block

            elif mode == 'ofb':
                decrypted_block = self._encrypt_block(IV, subkeys)
                IV = decrypted_block
                # Don't let _xor add more to the end of the decryptedblock when in ofb mode
                decrypted_block = self._xor(block, decrypted_block[:len(block)])
                decrypted_bits.extend(decrypted_block)

        final_bytes = self._bit_array_to_bytes(decrypted_bits)

        # only ecb and cbc will have padding
        if mode != 'ofb':
            final_bytes = self._rem_padding(final_bytes)

        final_output = ''

        # This will make the output a series of hex letters/characters
        if output_type == "hex":
            for byte in final_bytes:
                final_output += hex(byte)[2:].zfill(2)

        # I'm using this to get a string as output rather than bytestring
        elif output_type == "plaintext":
            final_output = final_bytes.decode('utf-8')

        return final_output
# __________________________________________________________________________________________


# __________________________________Not Used________________________________________________
def _leet_replace(word):
    """
    Replaces characters in a word with their leet equivalents
    :param word: The word to replace characters in
    :return: The word with leet characters replaced
    """
    new_word = ''
    leet_dic = {'a': '4', 'e': '3', 's': '5', 'o': '0', 'l': '1', 't': '7'}
    for c in word:
        if c in leet_dic:
            new_word += leet_dic[c]
        else:
            new_word += c
    return new_word
# __________________________________________________________________________________________


def _bytes_to_bit_array(byte_string):
    """
    Converts a byte string into an array of bits (list of integers 0/1).
    :param byte_string: The byte string to convert
    :return: The byte string converted into an array of bits
    """
    result = []
    for byte in byte_string:
        for bit in [7, 6, 5, 4, 3, 2, 1, 0]:
            mask = 1 << bit
            if byte & mask > 0:
                result.append(1)
            else:
                result.append(0)

    return result


def _bit_array_to_bytes(bit_array):
    """
    Converts an array of bits (list of integers 0/1) into a byte string.
    :param bit_array: The bit array to convert
    :return: The bit array converted into a byte string
    """
    result = []
    byte = 0

    for i, bit in enumerate(bit_array):
        byte += bit << (7 - (i % 8))
        if (i % 8) == 7:
            result += [byte]
            byte = 0

    if byte != 0:
        result += [byte]

    return bytes(result)


def CoolUserInterface():
    print("----------------------------------------------------------------------------------------------------")
    print("~                                                                                                  ~")
    print("~            ___                                    _     ___               _                      ~")
    print("~           / _ \__ _ ___ _____      _____  _ __ __|  |    / __\ __ __ _  ___|  |  _____ _ __          ~")
    print("~          / /_)/ _` / __/ __\ \ /\ / / _ \|  '__/ _` |   / / |  '__/ _` | / __|  | / / _ \ '__|          ~")
    print(
        "~         / ___/ (_|  \__ \__ \  V  V / (_) |  |  |  (_|  |  / /__|  |  |  (_|  |  (__|    <  __/ |             ~")
    print(
        "~         \/    \__,_| ___/___/ \_/\_/ \___/| _|   \__,_|  \____/_|   \__,_| \___| _| \_\___| _|             ~")
    print("~                                                                                                  ~")
    print("~                                                                                                  ~")
    print("                    Welcome user, frankly i dont care why you are using this.                      ~")
    print("~                   There are just a few things you should know before starting                    ~")


def main():
    CoolUserInterface()

    # This will start the timer
    start_time = time.time()

    # Loads the password dump file
    with open("pwdump.txt", "r") as f:
        pwdump = f.read()
        f.close()

    # Split the file into lines
    pwdump = pwdump.splitlines()
    # split the lines at the colons
    pwdump = [x.split(":") for x in pwdump]

    # Loads the password cracking dictionary
    with open("password_cracking_dictionary.txt", "r") as f:
        dictionary = f.read()
        f.close()
    # Split the file into lines
    dictionary = dictionary.splitlines()
    found = False

    # For each password in the password dump file:
    for line in pwdump:
        found = False
        currentUser = line[0]
        # Pop the last lines if they are empty
        while line[-1] == '':
            line.pop(-1)
        print("----------------------------------------------------------------------------------------------------")
        print("| Cracking password for user: " + currentUser)
        i = 0
        # a. For each word in the password cracking dictionary:
        for word in dictionary:
            i += 1
            # i. Calculate the LM hash of the word
            if len(word) < 8:
                continue
            # word = leet_replace(word)
            wordHash = LMHash(word).upper()
            # ii. If the LM hash of the word matches the LM hash of the password in the password dump file:
            # convert the hash in the password dump file to a string
            userHash = line[2]

            if i % 1000 == 0:
                print("| Attempted " + str(i) + " passwords, current password: " + word + " pass hash: " + line[2] +
                      ", current hash: " + wordHash)

            if str(wordHash) == str(userHash)[:16]:
                # 1. Print the username and password
                print("| Username: " + currentUser + " Password: " + word)
                # 2. Stop the timer
                stop_time = time.time()
                found = True
                # 3. Print the time it took to crack the password
                print("| Time to crack user" + currentUser + ": " + str(stop_time - start_time))
                # 4. Exit out of this loop
                break
        if not found:
            print("| Password not found for user: " + currentUser)
            stop_time = time.time()
            print("| Time to fail to crack user" + currentUser + ": " + str(stop_time - start_time))
            continue

    # Stop the timer
    stop_time = time.time()

    if not found:
        print("| Passwords not found")
        print("| Time to fail to crack all users: " + str(stop_time - start_time))
        sys.exit(0)

    print("----------------------------------------------------------------------------------------------------")
    print("| Time to crack all users: " + str(stop_time - start_time))
    print("--------------------------------------------END-----------------------------------------------------")
    sys.exit(0)


def LMHash(password):
    """
    Calculates the LM hash of a password
    :param password: The password to calculate the LM hash of
    :return: The LM hash of the password
    """

    # The user’s password is converted to uppercase
    password = password.upper()
    password = password.encode('utf-8')
    # If the password is longer than 14 characters, it is truncated to 14 characters
    if len(password) > 14:
        password = password[:14]

    # If the password is shorter than 14 characters, it is padded with null bytes to 14 characters
    elif len(password) < 14:
        password = password + b'\x00' * (14 - len(password))

    # The password is split into two 7-character chunks
    passkey = password[:7]

    # convert bytes to bits
    passkey = _bytes_to_bit_array(passkey)

    # insert a 0 every 7 bits
    for i in range(7, len(passkey), 8):
        passkey.insert(i, 0)
    # last 0 didn't get appended, so we do it manually
    passkey.append(0)

    # convert back to bytes
    passkey = _bit_array_to_bytes(passkey)

    # pad with null bytes again, so it is 8 characters long
    passkey = passkey + b"\x00" * (8 - len(passkey))

    # create des object
    des1 = DES(passkey)
    # encrypt the password with KGS!@#$%
    passkey = des1.encrypt(b"KGS!@#$%")

    return passkey


def bozo_test():
    password = 'armadillo'
    test = "CE2390AA223560BBE917F8D6FA472D2C"
    hash = LMHash(password)
    print(hash)
    assert hash == test


if __name__ == "__main__":
    #ZeroCool not working yet :/ sorry for so late hope you see the shared effort though :)
    main()
