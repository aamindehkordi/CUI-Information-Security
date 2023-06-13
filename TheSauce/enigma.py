#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Joshua Tallman
  @license: MIT Licence
  @contact: joshua.tallman@cui.edu
     @file: enigma.py
     @time: 2020-05-19 20:45
"""

# For encrypting and decrypting text messages using an Enigma simulator.


# German most common letters:
#  E: 16.4%
#  N:  9.8%
#  S:  7.3%
#  R:  7.0%
#  I:  6.6%
#  A:  6.5%

class m3:
    """ A class that implements the German M3 Enigma that was used by the Army
        and Navy in WWII. It has three rotors, a reflector, and a plugboard.
        There is another part that plays a very minor role in encryption, the
        rings, but these are not implemented for simplicity. It would be easy to
        add them by simply adjusting the initial counter values for each rotor.
    """

    def __init__(self, reflector="B",
                       left_rotor="III", middle_rotor="II", right_rotor="I",
                       left_start="A",   middle_start="A",  right_start="A",
                       left_ring="A",    middle_ring="A",   right_ring="A",
                       plugboard={}):
        """ Initializes the M3 Enigma machine by choosing which reflector and
            rotors to use and their initial settings (the letter showing in the
            top of the Enigma box). It also sets plugboard. If rings were added
            they would be set here.
        """
        self.reset(reflector,
                   left_rotor, middle_rotor, right_rotor,
                   left_start, middle_start, right_start,
                   left_ring,  middle_ring,  right_ring,
                   plugboard)

    def reset(self, reflector="B",
                    left_rotor="III", middle_rotor="II", right_rotor="I",
                    left_start="A",   middle_start="A",  right_start="A",
                    left_ring="A",    middle_ring="A",   right_ring="A",
                    plugboard=[]):
        """ Initializes the M3 Enigma machine by choosing which reflector and
            rotors to use and their initial settings (the letter showing in the
            top of the Enigma box). It also sets plugboard. If rings were added
            they would be set here.
        """
        self._reflector = _mechanical.reflector[reflector.upper()]
        self._L_rotor = _mechanical.rotor[left_rotor.upper()]
        self._M_rotor = _mechanical.rotor[middle_rotor.upper()]
        self._R_rotor = _mechanical.rotor[right_rotor.upper()]
        self._L_rotor["counter"] = (_letter_to_ordinal(left_start) - _letter_to_ordinal(left_ring)) % 26
        self._M_rotor["counter"] = (_letter_to_ordinal(middle_start) - _letter_to_ordinal(middle_ring)) % 26
        self._R_rotor["counter"] = (_letter_to_ordinal(right_start) - _letter_to_ordinal(right_ring)) % 26
        self._plugboard = { i:i for i in range(26) }
        for plug in plugboard:
            k1 = _letter_to_ordinal(plug[0])
            k2 = _letter_to_ordinal(plug[-1])
            self._plugboard[k1] = k2
            self._plugboard[k2] = k1

    def _step(self):
        """ Steps the rotors forward for a single keypress.
        """
        if self._M_rotor["counter"] == self._M_rotor["pushpeg"]:
            self._L_rotor["counter"] = (self._L_rotor["counter"] + 1) % 26
            self._M_rotor["counter"] = (self._M_rotor["counter"] + 1) % 26
        if self._R_rotor["counter"] == self._R_rotor["pushpeg"]:
            self._M_rotor["counter"] = (self._M_rotor["counter"] + 1) % 26
        self._R_rotor["counter"] = (self._R_rotor["counter"] + 1) % 26

    def _rotor(self, enter_wire, rotor, direction="forward"):
        """ Encrypts a signal passing through a single rotor.
        """
        rotor_indx = (enter_wire + rotor["counter"]) % 26
        leave_wire = (enter_wire + rotor[direction][rotor_indx]) % 26
        return leave_wire

    def _bounce_back(self, enter_wire, reflector):
        """ Encrypts a signal passing through the reflector.
        """
        leave_wire = (enter_wire + reflector[enter_wire]) % 26
        return leave_wire

    def keypress(self, letter, debug=False):
        """ Encrypts a single key pressed on the keyboard. Returns the _letter_to_ordinal
            that is lit on the lampboard.
        """
        # If the user entered punctuation, a number, or other symbol, just pass
        # it through without using the Enigma.
        if not isinstance(letter, str) or \
           len(letter) > 1 or \
           not letter.isalpha():
            return letter

        # Convert from a letter to a number
        # 1) Step the rotors forward
        # 2) Entry through the plugboard
        # 3) Entry through the three rotors
        # 4) Bounced back through the reflectors
        # 5) Return through the three rotors
        # 6) Return through the plugboard
        # Convert back from a number to a letter
        ch0 = _letter_to_ordinal(letter)
        self._step()
        ch1 = self._plugboard[ch0]
        ch2 = self._rotor(ch1, self._R_rotor, "forward")
        ch3 = self._rotor(ch2, self._M_rotor, "forward")
        ch4 = self._rotor(ch3, self._L_rotor, "forward")
        ch5 = self._bounce_back(ch4, self._reflector)
        ch6 = self._rotor(ch5, self._L_rotor, "reverse")
        ch7 = self._rotor(ch6, self._M_rotor, "reverse")
        ch8 = self._rotor(ch7, self._R_rotor, "reverse")
        ch9 = self._plugboard[ch8]
        if debug:
            L_letter = _ordinal_to_letter(self._L_rotor["counter"])
            M_letter = _ordinal_to_letter(self._M_rotor["counter"])
            R_letter = _ordinal_to_letter(self._R_rotor["counter"])
            m = "{0}{1}{2} {3} : {4} -> {5} -> {6} -> {7} | {8} -> {9} -> {10} -> {11} : {12}"
            print(m.format(L_letter, M_letter, R_letter,
                           _ordinal_to_letter(ch0), _ordinal_to_letter(ch1),
                           _ordinal_to_letter(ch2), _ordinal_to_letter(ch3),
                           _ordinal_to_letter(ch4), _ordinal_to_letter(ch5),
                           _ordinal_to_letter(ch6), _ordinal_to_letter(ch7),
                           _ordinal_to_letter(ch8), _ordinal_to_letter(ch9)))
        return _ordinal_to_letter(ch9)


def _letter_to_ordinal(letter):
    if letter.isalpha():
        if letter.islower():
            return ord(letter) - ord('a')
        else:
            return ord(letter) - ord('A')
    else:
        return letter

def _ordinal_to_letter(ordinal):
    if type(ordinal) == int:
        return chr(ordinal+ord('A'))
    else:
        return ordinal


class _mechanical:
    """ Technical specifications of the M3 Enigma mechnical parts based on the
        website http://users.telenet.be/d.rijmenants/en/enigmatech.htm
    """
    rotor = \
    {
      "I": {
        "forward": [ 4, 9, 10, 2, 7, 1, -3, 9, 13, -10, 3, 8, 2, 9, 10, -8, 7, 3, 0, -4, 6, 13, 5, -6, 4, 10 ],
        "reverse": [ -6, -5, -4, 3, -4, -2, -1, 8, -13, -10, -9, -7, -10, -3, -2, 4, -9, 6, 0, -8, -3, -13, -9, -7, -10, 10 ],
        "counter": 0,
        "pushpeg": 16
      },
      "II": {
        "forward": [ 0, 8, 1, 7, -12, 3, 11, 13, -11, -8, 1, -4, 10, 6, -2, 13, 0, -11, 7, -6, -5, 3, 9, -2, -10, 5 ],
        "reverse": [ 0, 8, -13, -1, -5, -9, 11, 4, -3, -8, -7, -1, 2, 6, 10, 5, 0, -11, 12, -6, -13, 2, -10, 11, -3, -7 ],
        "counter": 0,
        "pushpeg": 4
      },
      "III": {
        "forward": [ 1, 2, 3, 4, 5, 6, -4, 8, 9, 10, 13, 10, 13, 0, 10, -11, -8, 5, -12, 7, -10, -9, -2, -5, -8, -11 ],
        "reverse": [ -7, -1, 4, -2, 11, -3, 12, -4, 8, -5, 10, -6, 9, 0, 11, -8, 8, -9, 5, -10, 2, -10, -5, -13, -10, -13 ],
        "counter": 0,
        "pushpeg": 21
      },
      "IV": {
        "forward": [ 4, -9, 12, -8, 11, -6, 3, -7, -10, 7, 10, -3, 5, -6, 9, -4, -3, -12, 1, 13, -10, 8, 6, -11, -2, 2 ],
        "reverse": [ 7, -2, -6, -8, -4, 12, -13, 6, 3, -3, 10, 4, 11, 3, -12, -11, -7, -5, 9, -1, -10, 8, 2, -9, 10, 6 ],
        "counter": 0,
        "pushpeg": 9
      },
      "V": {
        "forward": [ -5, -2, -1, -12, 2, 3, 13, -9, 12, 6, 8, -8, 1, -6, -3, 8, 10, 5, -6, -10, -4, -7, 9, 7, 4, 11 ],
        "reverse": [ -10, 1, -4, 8, -7, -9, -2, 6, -3, 10, -11, 3, 6, -1, 7, -6, 4, 12, -8, -13, -12, 5, -5, -8, 9, 2 ],
        "counter": 0,
        "pushpeg": 25
      }
    }
    reflector = \
    {
      "B": [ -2, -10, -8, 4, 12, 13, 5, -4, 7, -12, 3, -5, 2, -3, -2, -7, -12, 10, -13, 6, 8, 1, -1, 12, 2, -6 ],
      "C": [ 5, -6, 13, 6, 4, -5, 8, -9, -4, -6, 7, -12, 11, 9, -8, -13, 3, -7, 2, -3, -2, 6, -9, -11, 9, 12 ]
    }


if __name__ == "__main__":

    import random
    rand0 = chr(random.randint(ord('A'), ord('Z')+1))
    rand1 = chr(random.randint(ord('A'), ord('Z')+1))
    rand2 = chr(random.randint(ord('A'), ord('Z')+1))
    my_enigma  = m3("B", "III", "II", "I", rand0, rand1, rand2)

    plaintext  = "In the beginning the Word already existed. The Word was " \
                 "with God, and the Word was God. He existed in the " \
                 "beginning with God. God created everything through him, " \
                 "and nothing was created except through him. The Word gave " \
                 "life to everything that was created, and his life brought " \
                 "light to everyone. The light shines in the darkness, and " \
                 "the darkness can never extinguish it."
    ciphertext = ""

    # Kinda clunky, our simulator acts like a typewriter, one key at a time
    print("Plaintext:", plaintext)
    for ch in plaintext:
        ciphertext += my_enigma.keypress(ch)
    print("\nCiphertext:", ciphertext)

    # Given the correct scramblers, brute forces the initial position using a
    # known-plaintext attack
    from itertools import product
    rotor = "abcdefghijklmnopqrstuvwxyz"
    for L_rotor, M_rotor, R_rotor in product(rotor, repeat=3):
        my_enigma = m3("B", "III", "II", "I", L_rotor, M_rotor, R_rotor)
        test_data = ""
        for ch in ciphertext:
            test_data += my_enigma.keypress(ch)
        if test_data == plaintext.upper():
            print("\nFound scrambler settings with known-plaintext attack");
            print("Left:  ", L_rotor.upper())
            print("Middle:", M_rotor.upper())
            print("Right: ", R_rotor.upper())
            exit(0)

    print("\nCould not brute-force the scrambler settings")
