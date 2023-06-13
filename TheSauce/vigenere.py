#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Joshua Tallman
  @license: MIT Licence
  @contact: joshua.tallman@cui.edu
     @file: vigenere.py
     @time: 2030-05-19 09:15
"""

# For encrypting and decrypting text with the Vigenere Cipher. Also includes
# several functions to assist with cryptanalysis.


import caesar as _caesar
import queue as _queue


def _get_space_positions(text):
    """ Returns a list containing the index of every space ' ' in a string.
    """
    return [pos for pos in range(len(text)) if text[pos] == " "]


def _insert_spaces(text, space_positions):
    """ Inserts spaces ' ' into a string at each index given in the list.
    """
    for pos in space_positions:
        text = text[:pos] + ' ' + text[pos:]
    return text


def _get_shift_factor(ch):
    """ Returns the base-0 ordinal of a letter (A->0, B->1, C->2, ...).
    """
    return ord(ch.lower()) - ord('a')


def encrypt(text, keyword, preserve_spaces=True):
    """ Encrypts a text with the Vigenere Cipher using the given keyword. By
        defualt, spaces in the plaintext are preserved. """

    # Save off the position of all the spaces, as we may reinsert them into them
    # them ciphertext. Although this is less secure, it does help us to
    # visualize the resulting ciphertext.
    if preserve_spaces is True:
        space_pos = _get_space_positions(text)
        plaintext = text.replace(' ', '')
    else:
        plaintext = text;

    # Repeat the keyword over and over again so that we have a key that is the
    # same length as the text itself.
    key = [keyword[i%len(keyword)] for i in range(len(plaintext))]

    # Convert the key into a series of shift amounts; e.g.,
    # [k, e, y, k, e, y, k...] ==> [11, 5, 25, 11, 5, 25, 11, ...]
    shifts = [_get_shift_factor(k) for k in key]

    # We encrypt the plaintext by using the shift amounts as a series of keys
    # to the the basic Caesar Shift Cipher.
    ciphertext = [_caesar.encrypt(ch, sh) for ch, sh in zip(plaintext, shifts)]
    ciphertext = ''.join(ciphertext).lower()

    # Put in the spaces that make the ciphertext easier to read
    if preserve_spaces is True:
        ciphertext = _insert_spaces(ciphertext, space_pos)

    return ciphertext


def decrypt(text, keyword):
    """ Decrypts a text with the Vigenere Cipher using the given keyword.
    """

    # We need to remove all of the spaces from the secret text in order for
    # decryption to work, but before doing that... save the location of the
    # spaces because we might want to reinsert them again later.
    space_pos  = _get_space_positions(text)
    ciphertext = text.replace(' ', '')

    # Repeat the keyword over and over again so that we have a key that is the
    # same length as the text itself.
    key = [keyword[i%len(keyword)] for i in range(len(ciphertext))]

    # Convert the key into a series of shift amounts; e.g.,
    # [k, e, y, k, e, y, k...] ==> [11, 5, 25, 11, 5, 25, 11, ...]
    shifts = [_get_shift_factor(k) for k in key]

    # We decrypt the ciphertext using the shift amounts as a series of keys
    # to the the basic Caesar Shift Cipher.
    plaintext = [_caesar.decrypt(ch, sh) for ch, sh in zip(ciphertext, shifts)]
    plaintext = ''.join(plaintext).lower()

    # Put any spaces back in for easy reading
    plaintext = _insert_spaces(plaintext, space_pos)

    return plaintext


def sequence_lists(text, count):
    """ Finds the index of all count-length sequences in the ciphertext and
        returns them in a dictionary. Used for cryptanalysis. All sequences are
        returned, but only repeated sequences have value.
        For a text of "ABCDABCD" and sequence length of 3, the function returns
          { "ABC":[0,4], "BCD":[1,5], "CDA":[2], "DAB":[3] }
    """
    sequences = {}
    lastIndex = len(text)-count
    for i in range(lastIndex+1):
        s = text[i:i+count]
        sequences[s] = sequences.get(s, [])
        sequences[s].append(i)
    return sequences


def sequence_span_lengths(sequences):
    """ Finds the space between each repeated sequence. Input is a dictionary
        of all sequences, as obtained from the `sequence_lists` function.
        Returns a dictionary with the sequence as the key and each span length
        as an element in a list. Used for cryptanalysis.
        For input { "ABC":[0,4], "BCD":[1,5], "CDA":[2], "DAB":[3] }, it returns
          { "ABC":[4], "BCD":[4] }
    """
    sequences = { seq:idx for seq, idx in sequences.items() if len(idx) > 1}
    spans = {}
    for s, indices in sequences.items():
        lastIndex = len(indices)-2
        spans[s]  = [(indices[i+1]-indices[i]) for i in range(lastIndex+1)]
    return spans


def _get_factor_list(n):
    """ Returns a list of all the factors for a number
    """
    return [i for i in range(2, n//2+1) if n % i == 0] + [n]


def sequence_length_factors(span):
    """ Calculates the factors for each provided sequence span length. Input is
        a dictionary of all sequences and their span length, as obtained from
        the `sequence_span_lengths` function. Returns a dictionary with them
        sequence as the key and a list of the factors. Note that 1 is omitted
        as a factor). Used for cryptanalysis.
        For input { "ABC":[4], "BCD":[4] }, it returns
          { "ABC":[2,4], "BCD":[2,4] }
    """
    factorLists = {}
    for spanSequence, spanLengthList in span.items():
        for spanLength in spanLengthList:
            if spanSequence not in factorLists:
                factorLists[spanSequence] = set(_get_factor_list(spanLength))
            else:
                factorLists[spanSequence].update(_get_factor_list(spanLength))
        factorLists[spanSequence] = sorted(list(factorLists[spanSequence]))
    return factorLists


def find_common_factors(factors):
    """ Finds the common factors within multiple groups of factors. Input is a
        dictionary of sequences and all the factors of their span length.
        Returns a list of any factors that are common to all sequences. Used for
        cryptanalysis.
        For input { "ABC":[2,4], "BCD":[4] }, it returns [4]
    """
    commonFactors = []
    allFactors = {f for factorList in factors.values() for f in factorList}
    for factor in allFactors:
        if all(factor in factorList for factorList in factors.values()):
            commonFactors.append(factor)
    return commonFactors


def split_ciphertext_by_key_length(ciphertext, key_length):
    """ Divides a Vigenere ciphertext into separate sub-ciphertexts, one for
        each letter of the key. Returns a list of sub-ciphertexts. There will
        be `key_length` number of sub-texts. Each sub-text corresponds to a
        different letter in the key. Used for cryptanalysis.
        For input "ABCDABCD" key_length=3, it returns [ "ADC", "BAD", "CB" ]
    """
    textList = [""] * key_length
    for startIndex in range(key_length):
        for idx in range(startIndex, len(ciphertext), key_length):
            textList[startIndex] += ciphertext[idx]
    return textList


def top3(subtext):
    """ Calculates the three most likely Vigenere shift factors for a group of
        subtext. Returns the shift facts as a list of tuples, each tuple having
        a score and the letter that corresponds to the shift factor.
        For example: [(48.5, 'P'), (459.6, 'E'), (468.6, 'A')]
    """
    q = _queue.PriorityQueue()
    scores = _caesar.score_all_keys(subtext)
    for i, score in scores.items():
        keyLetter = chr(i + ord('A'))
        q.put((round(score, 1), keyLetter))
    if q.qsize() != 26:
        err = "Error: Expected 26 scores but got {0}"
        raise IndexError(err.format(q.qsize()))
    return [q.get(), q.get(), q.get()]
