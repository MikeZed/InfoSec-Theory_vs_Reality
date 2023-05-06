"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


class AEAD(object):
    """
    Authenticated encryption and decryption
    """

    def __init__(self, block_len, mac_key, enc_key):
        self.block_len = block_len
        self.mac_key = mac_key
        self.enc_key = enc_key

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        raise NotImplementedError("Must override authenticated_enc")

    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        raise NotImplementedError("Must override authenticated_dec")


class AEAD_AES_128_CBC_HMAC_SHA_256(AEAD):
    def __init__(self, *args):
        self.block_len = 16
        self.mac_len = 16
        super(AEAD_AES_128_CBC_HMAC_SHA_256, self).__init__(
            self.block_len, *args)

    def __strip_padding(self, data):
        """
        Strip all padding from the data
        :param data: input data
        :return: stripped data
        """
        if len(data) % self.block_len != 0:
            return None

        padding_length = data[-1]
        padding = data[-(padding_length+1):]
        expected_padding = (chr(padding_length) * (padding_length+1)).encode()

        if padding != expected_padding:
            return None

        stripped_data = data[:-(padding_length+1)]
        return stripped_data

    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """
        padding_length = self.block_len - (len(data) % self.block_len) - 1
        padding = (chr(padding_length)
                   * (padding_length+1)).encode()
        padded_data = data + padding
        return padded_data

    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def __encrypt(self, p, nonce):
        """
        Encrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(p) + encryptor.finalize()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        TAG = self.__auth(aad + data)[:16]
        P = self.__pad(data + TAG)
        C = self.__encrypt(P, nonce)
        return C

    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """
        P = self.__decrypt(c, nonce)
        P = self.__strip_padding(P)

        # check if padding was valid
        if P is None:
            return None

        data, TAG = P[:-16], P[-16:]
        Expected_TAG = self.__auth(aad + data)[:16]
        
        if Expected_TAG != TAG:
            return None

        return data


if __name__ == "__main__":
    data = b'secret data'
    aad = b'more data'
    mac_key = urandom(16)
    enc_key = urandom(16)
    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    nonce = urandom(16)
    print(f"data = {data}")
    print(f"aad = {aad}")
    print(f"mac_key = {mac_key}")
    print(f"enc_key = {enc_key}")
    print(f"nonce = {nonce}")
    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    p = aead.authenticated_dec(ciphertext, aad, nonce)
    print(p)
    print(len(data))
    print(len(ciphertext))
