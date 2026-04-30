// XChaCha20-Poly1305 AEAD — MiniScript class
// IMPLEMENTED BY CLAUDE AI, IT WORKS BUT HAS NOT BEEN AUDITED.
// Usage:
//   cipher = new XChaCha20Poly1305
//   cipher.setKey("passwordpasswordpasswordpassword")  // 32-char ASCII key
//
//   hex = cipher.encrypt("hello!", "optional aad")    // nonce auto-generated
//   msg = cipher.decrypt(hex, "optional aad")         // null on auth failure
//
// Output format: 48 hex (nonce) + ciphertext hex + 32 hex (tag)

XChaCha20Poly1305 = {}

XChaCha20Poly1305.CONSTANTS = [1634760805, 857760878, 2036477234, 1797285236]  // "expand 32-byte k"
XChaCha20Poly1305.key = null   // set via setKey()

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

XChaCha20Poly1305.setKey = function(key)
    if not key isa string or len(key) != 32 then
        self.key = null
        return false
    end if
    self.key = key
    return true
end function

// ---------------------------------------------------------------------------
// ChaCha20 primitives
// ---------------------------------------------------------------------------

XChaCha20Poly1305.xor32 = function(a, b)   // 32-bit XOR via two 16-bit bitXor calls
    return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
end function

XChaCha20Poly1305.QR = function(s, a, b, c, d)  // Quarter-round in-place, rotl inlined
    s[a] = (s[a] + s[b]) % 4294967296
    t = self.xor32(s[d], s[a])
    s[d] = ((t % 65536) * 65536) + floor(t / 65536)            // rotl 16
    s[c] = (s[c] + s[d]) % 4294967296
    t = self.xor32(s[b], s[c])
    s[b] = ((t % 1048576) * 4096) + floor(t / 1048576)         // rotl 12
    s[a] = (s[a] + s[b]) % 4294967296
    t = self.xor32(s[d], s[a])
    s[d] = ((t % 16777216) * 256) + floor(t / 16777216)        // rotl 8
    s[c] = (s[c] + s[d]) % 4294967296
    t = self.xor32(s[b], s[c])
    s[b] = ((t % 33554432) * 128) + floor(t / 33554432)        // rotl 7
end function

XChaCha20Poly1305.rounds = function(s)  // 20 ChaCha20 rounds (10 double-rounds) in-place
    i = 0
    while i < 10
        self.QR(s, 0, 4, 8, 12)
        self.QR(s, 1, 5, 9, 13)
        self.QR(s, 2, 6, 10, 14)
        self.QR(s, 3, 7, 11, 15)
        self.QR(s, 0, 5, 10, 15)
        self.QR(s, 1, 6, 11, 12)
        self.QR(s, 2, 7, 8, 13)
        self.QR(s, 3, 4, 9, 14)
        i = i + 1
    end while
end function

XChaCha20Poly1305.block = function(subkey, counter, nonce_tail2)  // One 64-byte ChaCha20 block
    state = self.CONSTANTS + subkey + [counter, 0] + nonce_tail2
    s = state[:]
    self.rounds(s)
    i = 0
    while i < 16
        s[i] = (s[i] + state[i]) % 4294967296
        i = i + 1
    end while
    return s
end function

XChaCha20Poly1305.hchacha20 = function(packed_key, packed_nonce6)  // Derive 256-bit subkey
    s = self.CONSTANTS + packed_key + packed_nonce6[:4]
    self.rounds(s)
    return s[:4] + s[12:]
end function

XChaCha20Poly1305.applyKeystream = function(data, subkey, nonce_tail2)  // XOR data in-place; counter starts at 1
    n = len(data)
    i = 0
    blockIdx = 0
    shifts = [1, 256, 65536, 16777216]
    while i < n
        if i % 64 == 0 then
            s = self.block(subkey, blockIdx + 1, nonce_tail2)
            blockIdx = blockIdx + 1
        end if
        wi = floor(i / 4) % 16
        bi = i % 4
        data[i] = bitXor(data[i], floor(s[wi] / shifts[bi]) % 256)
        i = i + 1
    end while
end function

// ---------------------------------------------------------------------------
// Packing helpers
// ---------------------------------------------------------------------------

XChaCha20Poly1305.packKey = function(key)  // 32-char string -> 8 x 32-bit words
    words = []
    i = 0
    while i < 32
        words.push(code(key[i]) + code(key[i+1])*256 + code(key[i+2])*65536 + code(key[i+3])*16777216)
        i = i + 4
    end while
    return words
end function

XChaCha20Poly1305.packNonce = function(nonce)  // 24-byte list -> 6 x 32-bit words
    words = []
    i = 0
    while i < 24
        words.push(nonce[i] + nonce[i+1]*256 + nonce[i+2]*65536 + nonce[i+3]*16777216)
        i = i + 4
    end while
    return words
end function

XChaCha20Poly1305.unpack4 = function(w)  // 32-bit word -> 4 little-endian bytes
    return [w%256, floor(w/256)%256, floor(w/65536)%256, floor(w/16777216)%256]
end function

// ---------------------------------------------------------------------------
// UTF-8 codec
// ---------------------------------------------------------------------------

XChaCha20Poly1305.encode = function(s)  // String -> UTF-8 byte list
    ret = []
    i = 0
    while i < len(s)
        c = code(s[i])
        if c < 0 then
            return null
        else if c <= 127 then
            ret.push(c)
        else if c <= 2047 then
            ret.push(192 + floor(c / 64))
            ret.push(128 + c % 64)
        else if c <= 65535 then
            ret.push(224 + floor(c / 4096))
            ret.push(128 + floor(c / 64) % 64)
            ret.push(128 + c % 64)
        else if c <= 1114111 then
            ret.push(240 + floor(c / 262144))
            ret.push(128 + floor(c / 4096) % 64)
            ret.push(128 + floor(c / 64) % 64)
            ret.push(128 + c % 64)
        else
            return null
        end if
        i = i + 1
    end while
    return ret
end function

XChaCha20Poly1305.decode = function(bytes)  // UTF-8 byte list -> string
    ret = []
    i = 0
    while i < len(bytes)
        b = bytes[i]
        if b < 0 then
            return null
        else if b < 128 then
            ret.push(char(b))
            i = i + 1
        else if b < 224 and i < len(bytes) - 1 then
            ret.push(char((b - 192) * 64 + bytes[i+1] - 128))
            i = i + 2
        else if b < 240 and i < len(bytes) - 2 then
            ret.push(char((b - 224) * 4096 + (bytes[i+1] - 128) * 64 + bytes[i+2] - 128))
            i = i + 3
        else if b < 248 and i < len(bytes) - 3 then
            ret.push(char((b - 240) * 262144 + (bytes[i+1] - 128) * 4096 + (bytes[i+2] - 128) * 64 + bytes[i+3] - 128))
            i = i + 4
        else
            return null
        end if
    end while
    return join(ret, "")
end function

XChaCha20Poly1305.bytes2hex = function(bytes)
    hex = []
    wl = "0123456789abcdef"
    for b in bytes
        hex.push(wl[floor(b / 16)] + wl[b % 16])
    end for
    return join(hex, "")
end function

XChaCha20Poly1305.hex2bytes = function(hex)
    t = {"0":0,"1":1,"2":2,"3":3,"4":4,"5":5,"6":6,"7":7,"8":8,"9":9,
         "a":10,"b":11,"c":12,"d":13,"e":14,"f":15}
    hex = lower(hex)
    bytes = [0] * (len(hex) / 2)
    i = 0
    while i < len(bytes)
        bytes[i] = t[hex[i*2]] * 16 + t[hex[i*2+1]]
        i = i + 1
    end while
    return bytes
end function

// ---------------------------------------------------------------------------
// Poly1305 -- RFC 8439
// ---------------------------------------------------------------------------
// 130-bit arithmetic via 5 x 26-bit limbs (safe within float64 mantissa).
// p = 2^130 - 5

XChaCha20Poly1305.polyClampR = function(rb)  // Clamp r key bytes in-place
    rb[3]  = rb[3]  % 16
    rb[7]  = rb[7]  % 16
    rb[11] = rb[11] % 16
    rb[15] = rb[15] % 16
    rb[4]  = floor(rb[4]  / 4) * 4
    rb[8]  = floor(rb[8]  / 4) * 4
    rb[12] = floor(rb[12] / 4) * 4
end function

XChaCha20Poly1305.polyR2Limbs = function(rb)  // 16 r-bytes -> 5 x 26-bit limbs
    r0 = rb[0]  + rb[1]*256  + rb[2]*65536  + rb[3]*16777216
    r1 = rb[4]  + rb[5]*256  + rb[6]*65536  + rb[7]*16777216
    r2 = rb[8]  + rb[9]*256  + rb[10]*65536 + rb[11]*16777216
    r3 = rb[12] + rb[13]*256 + rb[14]*65536 + rb[15]*16777216
    rl = [0,0,0,0,0]
    rl[0] = r0 % 67108864
    rl[1] = floor(r0 / 67108864) + (r1 % 4096) * 64
    rl[2] = floor(r1 / 4096) + (r2 % 64) * 1048576
    rl[3] = floor(r2 / 64) + (r3 % 4) * 67108864
    rl[4] = floor(r3 / 4)
    return rl
end function

XChaCha20Poly1305.polyBlock = function(h, r, blk, hibit)  // Accumulate one Poly1305 block
    while len(blk) < 16; blk.push(0); end while
    m0 = blk[0]  + blk[1]*256  + blk[2]*65536  + blk[3]*16777216
    m1 = blk[4]  + blk[5]*256  + blk[6]*65536  + blk[7]*16777216
    m2 = blk[8]  + blk[9]*256  + blk[10]*65536 + blk[11]*16777216
    m3 = blk[12] + blk[13]*256 + blk[14]*65536 + blk[15]*16777216
    ml = [0,0,0,0,0]
    ml[0] = m0 % 67108864
    ml[1] = floor(m0 / 67108864) + (m1 % 4096) * 64
    ml[2] = floor(m1 / 4096) + (m2 % 64) * 1048576
    ml[3] = floor(m2 / 64) + (m3 % 4) * 67108864
    ml[4] = floor(m3 / 4) + hibit * 16777216
    h[0] = h[0] + ml[0]; h[1] = h[1] + ml[1]; h[2] = h[2] + ml[2]
    h[3] = h[3] + ml[3]; h[4] = h[4] + ml[4]
    // h = h * r  mod  2^130 - 5
    r0=r[0]; r1=r[1]; r2=r[2]; r3=r[3]; r4=r[4]
    h0=h[0]; h1=h[1]; h2=h[2]; h3=h[3]; h4=h[4]
    rr1=r1*5; rr2=r2*5; rr3=r3*5; rr4=r4*5
    d0 = h0*r0 + h1*rr4 + h2*rr3 + h3*rr2 + h4*rr1
    d1 = h0*r1 + h1*r0  + h2*rr4 + h3*rr3 + h4*rr2
    d2 = h0*r2 + h1*r1  + h2*r0  + h3*rr4 + h4*rr3
    d3 = h0*r3 + h1*r2  + h2*r1  + h3*r0  + h4*rr4
    d4 = h0*r4 + h1*r3  + h2*r2  + h3*r1  + h4*r0
    c = floor(d0 / 67108864); h[0] = d0 % 67108864; d1 = d1 + c
    c = floor(d1 / 67108864); h[1] = d1 % 67108864; d2 = d2 + c
    c = floor(d2 / 67108864); h[2] = d2 % 67108864; d3 = d3 + c
    c = floor(d3 / 67108864); h[3] = d3 % 67108864; d4 = d4 + c
    c = floor(d4 / 67108864); h[4] = d4 % 67108864
    h[0] = h[0] + c * 5
    c = floor(h[0] / 67108864); h[0] = h[0] % 67108864; h[1] = h[1] + c
end function

XChaCha20Poly1305.polyFinalise = function(h, sb)  // Finalise: reduce mod p, add s, return 16-byte tag
    // Propagate remaining carries
    c = floor(h[1] / 67108864); h[1] = h[1] % 67108864; h[2] = h[2] + c
    c = floor(h[2] / 67108864); h[2] = h[2] % 67108864; h[3] = h[3] + c
    c = floor(h[3] / 67108864); h[3] = h[3] % 67108864; h[4] = h[4] + c
    c = floor(h[4] / 67108864); h[4] = h[4] % 67108864; h[0] = h[0] + c * 5
    c = floor(h[0] / 67108864); h[0] = h[0] % 67108864; h[1] = h[1] + c
    // Conditionally subtract p = 2^130 - 5
    g0 = h[0] + 5
    c  = floor(g0 / 67108864); g0 = g0 % 67108864
    g1 = h[1] + c; c = floor(g1 / 67108864); g1 = g1 % 67108864
    g2 = h[2] + c; c = floor(g2 / 67108864); g2 = g2 % 67108864
    g3 = h[3] + c; c = floor(g3 / 67108864); g3 = g3 % 67108864
    g4 = h[4] + c - 67108864   // negative iff h < p
    if g4 < 0 then
        f0=h[0]; f1=h[1]; f2=h[2]; f3=h[3]; f4=h[4]
    else
        f0=g0; f1=g1; f2=g2; f3=g3; f4=g4
    end if
    // Reassemble 5 x 26-bit limbs -> 4 x 32-bit words
    bits52  = f0 + f1 * 67108864
    wd0     = bits52 % 4294967296
    wd1_lo  = floor(bits52 / 4294967296)
    bits104 = f2 + f3 * 67108864
    wd1     = wd1_lo + (bits104 % 4294967296)
    wd2     = floor(bits104 / 4294967296)
    wd2     = wd2 + floor(wd1 / 4294967296); wd1 = wd1 % 4294967296
    wd3     = f4 + floor(wd2 / 4294967296);  wd2 = wd2 % 4294967296
    wd3     = wd3 % 4294967296
    // Add s (mod 2^128)
    s0 = sb[0]  + sb[1]*256  + sb[2]*65536  + sb[3]*16777216
    s1 = sb[4]  + sb[5]*256  + sb[6]*65536  + sb[7]*16777216
    s2 = sb[8]  + sb[9]*256  + sb[10]*65536 + sb[11]*16777216
    s3 = sb[12] + sb[13]*256 + sb[14]*65536 + sb[15]*16777216
    t0 = wd0 + s0
    t1 = wd1 + s1 + floor(t0 / 4294967296)
    t2 = wd2 + s2 + floor(t1 / 4294967296)
    t3 = wd3 + s3 + floor(t2 / 4294967296)
    t0 = t0 % 4294967296; t1 = t1 % 4294967296
    t2 = t2 % 4294967296; t3 = t3 % 4294967296
    // Unpack to 16 bytes
    tag = []
    for w in [t0, t1, t2, t3]
        tag.push(w % 256)
        tag.push(floor(w / 256) % 256)
        tag.push(floor(w / 65536) % 256)
        tag.push(floor(w / 16777216) % 256)
    end for
    return tag
end function

XChaCha20Poly1305.poly1305 = function(key32, data)  // Compute 16-byte Poly1305 tag
    rb = key32[:16]; sb = key32[16:]
    self.polyClampR(rb)
    r = self.polyR2Limbs(rb)
    h = [0,0,0,0,0]
    i = 0; n = len(data)
    while i < n
        blen = n - i
        if blen > 16 then blen = 16
        hibit = 1
        if blen < 16 then hibit = 0
        self.polyBlock(h, r, data[i : i + blen], hibit)
        i = i + 16
    end while
    return self.polyFinalise(h, sb)
end function

XChaCha20Poly1305.macInput = function(aad_bytes, ct_bytes)  // RFC 8439 2.8 MAC input layout
    data = aad_bytes[:]
    if len(aad_bytes) % 16 != 0 then
        pad = 16 - len(aad_bytes) % 16
        i = 0; while i < pad; data.push(0); i = i + 1; end while
    end if
    for b in ct_bytes; data.push(b); end for
    if len(ct_bytes) % 16 != 0 then
        pad = 16 - len(ct_bytes) % 16
        i = 0; while i < pad; data.push(0); i = i + 1; end while
    end if
    for L in [len(aad_bytes), len(ct_bytes)]
        data.push(L % 256)
        data.push(floor(L / 256) % 256)
        data.push(floor(L / 65536) % 256)
        data.push(floor(L / 16777216) % 256)
        data.push(0); data.push(0); data.push(0); data.push(0)
    end for
    return data
end function

XChaCha20Poly1305.constEq = function(a, b)  // Constant-time byte list comparison
    if len(a) != len(b) then return false
    diff = 0; i = 0
    while i < len(a); diff = diff + abs(a[i] - b[i]); i = i + 1; end while
    return diff == 0
end function

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

XChaCha20Poly1305.encrypt = function(msg, aad="", nonce=null)
    if self.key == null then return null

    if not nonce isa list or len(nonce) != 24 then
        nonce = []; i = 0
        while i < 24; nonce.push(floor(rnd * 256)); i = i + 1; end while
    end if

    packed_key   = self.packKey(self.key)
    packed_nonce = self.packNonce(nonce)
    subkey       = self.hchacha20(packed_key, packed_nonce)
    tail2        = packed_nonce[4:]

    // Poly1305 one-time key: first 32 bytes of counter-0 block
    pb = self.block(subkey, 0, tail2)
    poly_key = []
    i = 0; while i < 8; poly_key = poly_key + self.unpack4(pb[i]); i = i + 1; end while

    msg_bytes = self.encode(msg)
    if msg_bytes == null then return null
    aad_bytes = self.encode(aad)
    if aad_bytes == null then return null

    self.applyKeystream(msg_bytes, subkey, tail2)   // encrypt in-place
    tag = self.poly1305(poly_key, self.macInput(aad_bytes, msg_bytes))

    return self.bytes2hex(nonce + msg_bytes + tag)
end function

XChaCha20Poly1305.decrypt = function(hex_in, aad="")
    if self.key == null then return null
    if not hex_in isa string or len(hex_in) < 80 or len(hex_in) % 2 != 0 then return null

    all      = self.hex2bytes(hex_in)
    nonce    = all[:24]
    tag_recv = all[len(all)-16:]
    ct       = all[24 : len(all)-16]

    packed_key   = self.packKey(self.key)
    packed_nonce = self.packNonce(nonce)
    subkey       = self.hchacha20(packed_key, packed_nonce)
    tail2        = packed_nonce[4:]

    pb = self.block(subkey, 0, tail2)
    poly_key = []
    i = 0; while i < 8; poly_key = poly_key + self.unpack4(pb[i]); i = i + 1; end while

    aad_bytes = self.encode(aad)
    if aad_bytes == null then return null

    // Verify tag BEFORE decrypting (authenticate-then-decrypt)
    tag_calc = self.poly1305(poly_key, self.macInput(aad_bytes, ct))
    if not self.constEq(tag_calc, tag_recv) then return null

    self.applyKeystream(ct, subkey, tail2)   // decrypt in-place
    return self.decode(ct)
end function

// ---------------------------------------------------------------------------
// Self-test, remove everything below.
// ---------------------------------------------------------------------------

cipher = new XChaCha20Poly1305
cipher.setKey("passwordpasswordpasswordpassword")

aad = "authenticated header"
msg = "Hello, XChaCha20-Poly1305!"
hex = cipher.encrypt(msg, aad)
print "Ciphertext (hex): " + hex
dec = cipher.decrypt(hex, aad)
print "Decrypted:        " + dec
print "Round-trip OK:    " + str(dec == msg)

tampered = hex[:50] + "ff" + hex[52:]
print "Tamper detected:  " + str(cipher.decrypt(tampered, aad) == null)
print "Wrong AAD:        " + str(cipher.decrypt(hex, "wrong aad") == null)

c2 = new XChaCha20Poly1305
c2.setKey("wrongkeywrongkeywrongkeywrongkey")
print "Wrong key:        " + str(c2.decrypt(hex, aad) == null)
