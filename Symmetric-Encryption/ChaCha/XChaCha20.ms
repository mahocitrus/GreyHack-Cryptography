// Self-contained XChaCha20 encryption and decryption. without AEAD but confidentiality remains.
// Use XChaCha20_Poly1305.ms instead.

XChaCha20_encrypt = function(msg, key, nonce) // self-contained encryption function, generate random nonce if no nonce supplied.
    _constants = [1634760805, 857760878, 2036477234, 1797285236] // "expand 32-byte k"
    _shift = [1, 256, 65536, 16777216]
    _xor = function(a, b)
        return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
    end function
    _QR = function(s, a, b, c, d) // A quarter-round, manipulate s in-place, rotl are inlined
        s[a] = (s[a] + s[b]) % 4294967296
        s[d] = _xor(s[d], s[a])
        s[d] = ((s[d] % 65536) * 65536) + floor(s[d] / 65536)
        s[c] = (s[c] + s[d]) % 4294967296
        s[b] = _xor(s[b], s[c])
        s[b] = ((s[b] % 1048576) * 4096) + floor(s[b] / 1048576)
        s[a] = (s[a] + s[b]) % 4294967296
        s[d] = _xor(s[d], s[a])
        s[d] = ((s[d] % 16777216) * 256) + floor(s[d] / 16777216)
        s[c] = (s[c] + s[d]) % 4294967296
        s[b] = _xor(s[b], s[c])
        s[b] = ((s[b] % 33554432) * 128) + floor(s[b] / 33554432)
    end function
    _rounds = function(s) // 20 rounds, manipulate s in-place
        i = 0
        while i < 10
            _QR(s, 0, 4, 8, 12) // column
            _QR(s, 1, 5, 9, 13)
            _QR(s, 2, 6, 10, 14)
            _QR(s, 3, 7, 11, 15)
            _QR(s, 0, 5, 10, 15) // diagonal
            _QR(s, 1, 6, 11, 12)
            _QR(s, 2, 7, 8, 13)
            _QR(s, 3, 4, 9, 14)
            i = i + 1
        end while
    end function
    _bytes2hex = function(bytes)
        hex = []
        wordlist = "0123456789abcdef"
        for byte in bytes
            if byte >= 256 then return null
            push(hex, wordlist[floor(byte / 16)] + wordlist[byte % 16])
        end for
        return join(hex, "")
    end function
    _encode = function(s) // Convert string to bytes.
        ret = []
        i = 0
        while i < len(s)
            c = code(s[i])
            if c < 0 then
                return null
            else if c <= 127 then
                push(ret, c)
            else if c <= 2047 then
                push(ret, 192 + floor(c / 64))
                push(ret, 128 + c % 64)
            else if c <= 65535 then
                push(ret, 224 + floor(c / 4096))
                push(ret, 128 + floor(c / 64) % 64)
                push(ret, 128 + c % 64)
            else if c <= 1114111 then
                push(ret, 240 + floor(c / 262144))
                push(ret, 128 + floor(c / 4096) % 64)
                push(ret, 128 + floor(c / 64) % 64)
                push(ret, 128 + c % 64)
            else
                return null
            end if
            i = i + 1
        end while
        return ret
    end function

    if not nonce isa list or len(nonce) != 24 then
        nonce = []
        for i in range(0, 23)
            push(nonce, floor(rnd * 256))
        end for
    end if
    if not key isa string or len(key) != 32 then return null
    key_bytes = []
    for k in key
        key_bytes.push(code(k))
    end for
    packed_key = []
    for i in range(0, len(key_bytes) - 1, 4)
        push(packed_key, key_bytes[i] + (key_bytes[i+1] * 256) + (key_bytes[i+2] * 65536) + (key_bytes[i+3]*16777216))
    end for
    packed_nonce = []
    for i in range(0, len(nonce) - 1, 4)
        push(packed_nonce, nonce[i] + (nonce[i+1] * 256) + (nonce[i+2] * 65536) + (nonce[i+3]*16777216))
    end for
    hstate = _constants + packed_key + packed_nonce[:4]
    _rounds(hstate)
    subkey = hstate[:4] + hstate[12:]
    cipherbytes = _encode(msg)
    i = 0
    while i < len(cipherbytes)
        if i % 64 == 0 then
            hi = floor((i / 64) / 4294967296)
            lo = (i / 64) % 4294967296
            state = _constants + subkey + [hi, lo] + packed_nonce[4:]
            s = state[:]
            _rounds(s)
            j = 0
            while j < len(s)
                s[j] = (s[j] + state[j]) % 4294967296
                j = j + 1
            end while
        end if
        if i % 16 == 0 then word = s[i % 16]
        cipherbytes[i] = bitXor(cipherbytes[i], floor(word / _shift[i % 4]) % 256)
        i = i + 1
    end while
    return _bytes2hex(nonce + cipherbytes)
end function
XChaCha20_decrypt = function(cipher, key) // self-contained decryption function, gets nonce from the first 192 bits of the cipher.
    _constants = [1634760805, 857760878, 2036477234, 1797285236] // "expand 32-byte k"
    _shift = [1, 256, 65536, 16777216]
    _xor = function(a, b)
        return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
    end function
    _QR = function(s, a, b, c, d) // A quarter-round, manipulate s in-place, rotl are inlined
        s[a] = (s[a] + s[b]) % 4294967296
        s[d] = _xor(s[d], s[a])
        s[d] = ((s[d] % 65536) * 65536) + floor(s[d] / 65536)
        s[c] = (s[c] + s[d]) % 4294967296
        s[b] = _xor(s[b], s[c])
        s[b] = ((s[b] % 1048576) * 4096) + floor(s[b] / 1048576)
        s[a] = (s[a] + s[b]) % 4294967296
        s[d] = _xor(s[d], s[a])
        s[d] = ((s[d] % 16777216) * 256) + floor(s[d] / 16777216)
        s[c] = (s[c] + s[d]) % 4294967296
        s[b] = _xor(s[b], s[c])
        s[b] = ((s[b] % 33554432) * 128) + floor(s[b] / 33554432)
    end function
    _rounds = function(s) // 20 rounds, manipulate s in-place
        i = 0
        while i < 10
            _QR(s, 0, 4, 8, 12) // column
            _QR(s, 1, 5, 9, 13)
            _QR(s, 2, 6, 10, 14)
            _QR(s, 3, 7, 11, 15)
            _QR(s, 0, 5, 10, 15) // diagonal
            _QR(s, 1, 6, 11, 12)
            _QR(s, 2, 7, 8, 13)
            _QR(s, 3, 4, 9, 14)
            i = i + 1
        end while
    end function
    _hex2bytes = function(hex)
        table = {"0":0, "1":1, "2":2, "3":3, "4":4, "5":5, "6":6, "7":7, "8":8, "9":9, "a":10, "b":11, "c":12, "d":13, "e":14, "f":15}
        hex = lower(hex)
        bytes = [0] * (len(hex) / 2)
        i = 0
        while i < len(bytes)
            bytes[i] = (table[hex[i * 2]] * 16) + table[hex[i * 2 + 1]]
            i = i + 1
        end while
        return bytes
    end function
    _decode = function(bytes) // Convert bytes(list of 8 bits unsigned integers) to string.
        i = 0
        ret = []
        while i < len(bytes)
            if bytes[i] < 0 then
                return null
            else if bytes[i] < 128 then
                push(ret, char(bytes[i]))
                i = i + 1
            else if bytes[i] < 224 and i < len(bytes) - 1 then
                push(ret, char((bytes[i] - 192) * 64 + bytes[i + 1] - 128))
                i = i + 2
            else if bytes[i] < 240 and i < len(bytes) - 2 then
                push(ret, char((bytes[i] - 224) * 4096 + (bytes[i + 1] - 128) * 64 + bytes[i + 2] - 128))
                i = i + 3
            else if bytes[i] < 248 and i < len(bytes) - 3 then
                push(ret, char((bytes[i] - 240) * 262144 + (bytes[i + 1] - 128) * 4096 + (bytes[i + 2] - 128) * 64 + bytes[i + 3] - 128))
                i = i + 4
            else
                return null
            end if
        end while
        return join(ret, "")
    end function

    if not key isa string or len(key) != 32 then return null
    key_bytes = []
    for k in key
        key_bytes.push(code(k))
    end for
    cipherbytes = _hex2bytes(cipher)
    nonce = cipherbytes[:24]
    cipherbytes = cipherbytes[24:]
    packed_key = []
    for i in range(0, len(key_bytes) - 1, 4)
        push(packed_key, key_bytes[i] + (key_bytes[i+1] * 256) + (key_bytes[i+2] * 65536) + (key_bytes[i+3]*16777216))
    end for
    packed_nonce = []
    for i in range(0, len(nonce) - 1, 4)
        push(packed_nonce, nonce[i] + (nonce[i+1] * 256) + (nonce[i+2] * 65536) + (nonce[i+3]*16777216))
    end for
    hstate = _constants + packed_key + packed_nonce[:4]
    _rounds(hstate)
    subkey = hstate[:4] + hstate[12:]
    i = 0
    while i < len(cipherbytes)
        if i % 64 == 0 then
            hi = floor((i / 64) / 4294967296)
            lo = (i / 64) % 4294967296
            state = _constants + subkey + [hi, lo] + packed_nonce[4:]
            s = state[:]
            _rounds(s)
            j = 0
            while j < len(s)
                s[j] = (s[j] + state[j]) % 4294967296
                j = j + 1
            end while
        end if
        if i % 16 == 0 then word = s[i % 16]
        cipherbytes[i] = bitXor(cipherbytes[i], floor(word / _shift[i % 4]) % 256)
        i = i + 1
    end while
    return _decode(cipherbytes)
end function
start = time
XChaCha20_decrypt(XChaCha20_encrypt("chacha20" * 128, "passwordpasswordpasswordpassword"), "passwordpasswordpasswordpassword")
print time - start