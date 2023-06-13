#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Joshua Tallman
  @license: MIT Licence
  @contact: joshua.tallman@cui.edu
     @file: caesar.py
     @time: 2030-05-19 09:15
"""

# For encrypting and decrypting text with the Caesar Shift Cipher. Also includes
# several functions to assist with cryptanalysis

from matplotlib import pyplot as _plt


english_alphabet = "abcdefghijklmnopqrstuvwxyz"
english_frequencies = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.2, 0.8,
                       4.0, 2.4, 6.7, 7.5,  1.9, 0.1, 6.0, 6.3, 9.1, 2.8, 1.0,
                       2.4, 0.2, 2.0, 0.1]


def words_to_ordinals(input_string):
    """ Converts an ASCII string to a list of ordinals. Output list has the
        same number of items as the input string's length. Non-alphabetic chars
        are copied to the output without any modification (spaces, punctuation,
        numbers, etc.).
    """
    zeroed_ordinals = []
    for letter in input_string:
        if letter.isalpha():
            if letter.islower():
                zeroed_ordinals.append(ord(letter) - ord('a'))
            else:
                zeroed_ordinals.append(ord(letter) - ord('A'))
        else:
            zeroed_ordinals.append(letter)
    return zeroed_ordinals


def ordinals_to_words(input_string):
    """ Converts a list of ordinals to a list of letters. Output list has the
        same number of items as the input list's length. Non-alphabetic ordinals
        are copied to the output without any modification (spaces, punctuation,
        numbers, etc.).
    """
    letter_string = []
    for ordinal in input_string:
        if type(ordinal) == int:
            letter_string.append(chr(ordinal+ord('A')))
        else:
            letter_string.append(ordinal)
    return letter_string


def _caesar_rotate(letter, shift_count):
    """ Shifts a single ordinal by amount specified in the key.
    """
    return (letter + shift_count) % 26


def _caesar_shift_ordinals(original_ordinals, key):
    """ Shifts a list of ordinals by the amount specified in the key. Non-
        ordinals like spaces, punctuation, and numbers are copied to the output
        without any modification. Returns a list.
    """
    shifted_ordinals = []
    for ordinal in original_ordinals:
        if type(ordinal) == int:
            shifted_ordinals.append(_caesar_rotate(ordinal, key))
        else:
            shifted_ordinals.append(ordinal)
    return shifted_ordinals


def encrypt(plaintext, key):
    """ Encrypts using the Caesar Shift Cipher with the given key
    """
    plaintext_as_ordinals = words_to_ordinals(plaintext)
    ciphertext_as_ordinals = _caesar_shift_ordinals(plaintext_as_ordinals, key)
    ciphertext_as_list = ordinals_to_words(ciphertext_as_ordinals)
    ciphertext = "".join(ciphertext_as_list)
    return ciphertext


def decrypt(ciphertext, key):
    """ Decrypts using the Caesar Shift Cipher with the given key
    """
    ciphertext_as_ordinals = words_to_ordinals(ciphertext)
    plaintext_as_ordinals = _caesar_shift_ordinals(ciphertext_as_ordinals, -key)
    plaintext_as_list = ordinals_to_words(plaintext_as_ordinals)
    plaintext = "".join(plaintext_as_list)
    return plaintext


def brute_force(ciphertext):
    """ Prints all 26 possible decryptions for the Caesar Shift Cipher. If the
        ciphertext is long, this will produce a messy output.
    """
    for i in range(26):
        print(decrypt(ciphertext, i))


def calculate_frequencies(ciphertext):
    """ Calculates the frequency of each English letter in the text. Returns a
        list of 26 frequencies [A..Z].
    """
    frequencies = []
    ciphertext = ciphertext.lower()
    for ch in english_alphabet:
        count = ciphertext.count(ch)
        frequencies.append(100.0 * count / len(ciphertext))
    return frequencies


def plot_frequencies(ciphertext, guessed_key=0, width=10, height=5):
    """ Plots the frequency of each letter [A..Z] in a ciphertext and compares
        it to a plot of the standard English distribution. The standard English
        plot is on top and the ciphertext plot is on the bottom.
    """
    # shift the ciphertext according to the guess (default is 0 for no shift)
    ciphertext = decrypt(ciphertext, guessed_key)
    label = "Key=" + str(guessed_key)

    # calculate the x & y values
    x = list(english_alphabet)
    y1 = english_frequencies
    y2 = calculate_frequencies(ciphertext)

    # plot the two graphs
    _plt.figure(figsize=(width, height))
    _plt.subplot(2,1,1)                                # standard english graph
    _plt.text(-1, max(y1)-1, 'English', fontsize=15)
    _plt.bar(x, y1, width=0.35, color='k', align='center')
    _plt.xticks(x)
    _plt.subplot(2,1,2)                                # ciphertext graph
    _plt.text(-1, max(y2)-1, label, fontsize=15, color='b')
    _plt.bar(x, y2, width=0.35, color='b', align='center')
    _plt.xticks(x)
    _plt.show()


def score_frequencies(frequency_distribution):
    """ Scores a ciphertext distribution [A..Z] aginst the standard English
        frequency distribution. Input is a 26-item list of frequencies, whose
        sum should add up to 100. Returns a score value. Lower scores match
        English closer than higher scores.
    """
    # Score for each letter is the frequency difference between this letter
    # and english (e.g., 7.4% - 3.9%), squared.
    # Total score is sum of the invidual scores.
    score = 0.0
    for i in range(26):
        frequency = frequency_distribution[i]
        standard  = english_frequencies[i]
        score += (frequency - standard) ** 2
    score = round(score, 1)
    return score


def score_all_keys(ciphertext):
    """ Scores the ciphertext using all 26 possible keys and returns a list of
        all 26 scores. Returns a dictionary with each key being the encryption
        key and each value being the frequency score. Lowest score is most
        likely to belong to the correct Caesar Shift Cipher key.
    """
    # 1. Decrypt the ciphertext with one of the 26 possible keys
    # 2. Calculate the frequncy distribution of each letter_string
    # 3. Calculate the score for this frequency distribution
    frequency_list = {}
    for shift in range(26):
        possible_plaintext     = decrypt(ciphertext, shift)
        frequency_distribution = calculate_frequencies(possible_plaintext)
        frequency_score        = score_frequencies(frequency_distribution)
        frequency_list[shift]  = frequency_score
    return frequency_list


_plaintext = "Beware of the badgers, they are ferocious and have a mean streak"
if __name__ == "__main__":
    key = 11
    print("Caesar Shift Cipher demo")
    print("ORIGINAL: ", _plaintext)
    encrypted = encrypt(_plaintext, key)
    plot_frequencies(encrypted)
    print("ENCRYPTED:", encrypted)
    decrypted = decrypt(encrypted, key)
    print("DECRYPTED:", decrypted)
    print("done")
