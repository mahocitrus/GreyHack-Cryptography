ChaCha20 = {} // This is not an object-oriented ChaCha20 class, this class contains primitives for ChaCha20.
ChaCha20._constants = [1634760805, 857760878, 2036477234, 1797285236] // "expand 32-byte k"
ChaCha20._add = function(a, b)
    return (a + b) % 4294967296
end function
ChaCha20._xor = function(a, b)
    return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
end function
ChaCha20._QR = function(s, a, b, c, d) //rotl are inlined
    s[a] = self._add(s[a], s[b])
    s[d] = self._xor(s[d], s[a])
    s[d] = ((s[d] % 65536) * 65536) + floor(s[d] / 65536)
    s[c] = self._add(s[c], s[d])
    s[b] = self._xor(s[b], s[c])
    s[b] = ((s[b] % 1048576) * 4096) + floor(s[b] / 1048576)
    s[a] = self._add(s[a], s[b])
    s[d] = self._xor(s[d], s[a])
    s[d] = ((s[d] % 16777216) * 256) + floor(s[d] / 16777216)
    s[c] = self._add(s[c], s[d])
    s[b] = self._xor(s[b], s[c])
    s[b] = ((s[b] % 33554432) * 128) + floor(s[b] / 33554432)
end function
ChaCha20._block = function(state)
    s = state[:]
    for i in range(1, 10)
        self._QR(s, 0, 4, 8, 12) // column
        self._QR(s, 1, 5, 9, 13)
        self._QR(s, 2, 6, 10, 14)
        self._QR(s, 3, 7, 11, 15)
        self._QR(s, 0, 5, 10, 15) // diagonal
        self._QR(s, 1, 6, 11, 12)
        self._QR(s, 2, 7, 8, 13)
        self._QR(s, 3, 4, 9, 14)
    end for
    key_stream = []
    for i in range(0, 15)
        word = self._add(s[i], state[i])
        push(key_stream, word % 256)
        push(key_stream, floor(word / 256) % 256)
        push(key_stream, floor(word / 65536) % 256)
        push(key_stream, floor(word / 16777216))
    end for
    return key_stream
end function

XChaCha20 = new ChaCha20 //XChaCha20 primitives
XChaCha20._HChaCha20 = function(key, nonce)
    s = self._constants[:]
    for i in range(0, 31, 4)
        push(s, key[i] + (key[i+1] * 256) + (key[i+2] * 65536) + (key[i+3]*16777216))
    end for
    for i in range(0, 15, 4)
        push(s, nonce[i] + (nonce[i+1] * 256) + (nonce[i+2] * 65536) + (nonce[i+3]*16777216))
    end for
    for i in range(1, 10)
        self._QR(s, 0, 4, 8, 12); self._QR(s, 1, 5, 9, 13)
        self._QR(s, 2, 6, 10, 14); self._QR(s, 3, 7, 11, 15)
        self._QR(s, 0, 5, 10, 15); self._QR(s, 1, 6, 11, 12)
        self._QR(s, 2, 7, 8, 13); self._QR(s, 3, 4, 9, 14)
    end for
    return s[:4] + s[12:] // wordsize 32bits, directly feed into chacha20 without packing and unpacking.
end function

chacha20_encrypt = function(key, nonce, plaintext) // key, nonce, plaintext are all bytes.
    packed_key = []
    for i in range(0, 31, 4)
        push(packed_key, key[i] + (key[i+1] * 256) + (key[i+2] * 65536) + (key[i+3]*16777216)) // little-endian key, 256-bits.
    end for
    packed_nonce = []
    for i in range(0, 11, 4)
        push(packed_nonce, nonce[i] + (nonce[i+1] * 256) + (nonce[i+2] * 65536) + (nonce[i+3]*16777216)) //little-endian nonce, 96-bits RFC 8439.
    end for
    key_stream = []
    for i in range(0, floor(len(plaintext) / 64))
        key_stream = key_stream + ChaCha20._block(ChaCha20._constants + packed_key + [i] + packed_nonce)
    end for
    ciphertext = []
    for i in indexes(plaintext)
        push(ciphertext, bitXor(plaintext[i], key_stream[i]))
    end for
    return ciphertext
end function
chacha20_decrypt = function(key, nonce, ciphertext)  // key, nonce, ciphertext are all bytes.
    return chacha20_encrypt(key, nonce, ciphertext)
end function

xchacha20_encrypt = function(key, nonce24, plaintext)
    subkey = XChaCha20._HChaCha20(key, nonce24[:16])
    nonce = nonce24[16:]
    packed_nonce = []
    for i in range(0, 7, 4)
        push(packed_nonce, nonce[i] + (nonce[i+1] * 256) + (nonce[i+2] * 65536) + (nonce[i+3]*16777216)) //little-endian nonce
    end for
    key_stream = []
    for i in range(0, floor(len(plaintext) / 64))
        lo = i % 4294967296
        hi = floor(i / 4294967296)
        key_stream = key_stream + ChaCha20._block(ChaCha20._constants + subkey + [hi, lo] + packed_nonce)
    end for
    ciphertext = []
    for i in indexes(plaintext)
        push(ciphertext, bitXor(plaintext[i], key_stream[i]))
    end for
    return ciphertext
end function