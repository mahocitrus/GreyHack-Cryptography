//Author: mahocitrus
//This is probably as secure as than the old sha256 by finko.

uint64 = {}
uint64.init = function(self, lo, hi)
    ret = new self
    ret.lo = lo
    ret.hi = hi
    return ret
end function
uint64.XOR = function(self, other)
    XOR = function(a, b)
        return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
    end function
    return uint64.init(XOR(self.lo, other.lo), XOR(self.hi, other.hi))
end function
uint64.NOT = function(self)
    NOT = function(n)
        return 4294967295 - n
    end function
    return uint64.init(NOT(self.lo), NOT(self.hi))
end function
uint64.AND = function(self, other)
    AND = function(a, b)
        return bitAnd(floor(a / 65536), floor(b / 65536)) * 65536 + bitAnd(a % 65536, b % 65536)
    end function
    return uint64.init(AND(self.lo, other.lo), AND(self.hi, other.hi))
end function
uint64.shiftr = function(self, n)
    return uint64.init(floor(self.lo / (2 ^ n)), floor(self.hi / (2 ^ n)))
end function
uint64.rotl64 = function(self, n)
    rotl64 = function(lo, hi, n)
        n = n % 64
        if n == 0 then return uint64.init(lo, hi)
        if n < 32 then
            pow_n = 2 ^ n
            pow_32_n = 2 ^ (32 - n)
            new_lo = ((lo * pow_n) % 4294967296 + floor(hi / pow_32_n)) % 4294967296
            new_hi = ((hi * pow_n) % 4294967296 + floor(lo / pow_32_n)) % 4294967296
            return uint64.init(new_lo, new_hi)
        else
            return rotl64(hi, lo, n - 32)
        end if
    end function
    return rotl64(self.lo, self.hi, n)
end function

SHAKE128 = {}
SHAKE128.RC = [[1, 0], [32898, 0], [32906, 2147483648], [2147516416, 2147483648], [32907, 0], [2147483649, 0], [2147516545, 2147483648], [32777, 2147483648], [138, 0], [136, 0], [2147516425, 0], [2147483658, 0], [2147516555, 0], [139, 2147483648], [32905, 2147483648], [32771, 2147483648], [32770, 2147483648], [128, 2147483648], [32778, 0], [2147483658, 2147483648], [2147516545, 2147483648], [32896, 2147483648], [2147483649, 0], [2147516424, 2147483648]]
SHAKE128.ROT = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ]
SHAKE128.iota = function(A, n)
    XOR = function(a, b)
        return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
    end function
    A[0][0].lo = XOR(A[0][0].lo, self.RC[n][0])
    A[0][0].hi = XOR(A[0][0].hi, self.RC[n][1])
end function
SHAKE128.theta = function(A)
    C = []
    D = []
    for x in range(0, 4)
        C.push(uint64.init(0))
        D.push(uint64.init(0))
    end for
    for x in range(0, 4)
        C[x] = A[x][0].XOR(A[x][1]).XOR(A[x][2]).XOR(A[x][3]).XOR(A[x][4])
    end for
    for x in range(0, 4)
        D[x] = C[(x - 1) % 5].XOR(C[(x + 1) % 5].rotl64(1))
    end for
    for x in range(0, 4)
        for y in range(0, 4)
            A[x][y] = A[x][y].XOR(D[x])
        end for
    end for
end function
SHAKE128.rho_pi = function(A)
    B = [[0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]
    for i in range(0, 4)
        for j in range(0, 4)
            B[i][j] = uint64.init(0, 0)
        end for
    end for
    for x in range(0, 4)
        for y in range(0, 4)
            B[y][(2 * x + 3 * y) % 5] = A[x][y].rotl64(self.ROT[x][y])
        end for
    end for
    return B
end function
SHAKE128.chi = function(A)
    B = [[0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]
    for i in range(0, 4)
        for j in range(0, 4)
            B[i][j] = uint64.init(0, 0)
        end for
    end for
    for x in range(0, 4)
        for y in range(0, 4)
            B[x][y] = A[x][y].XOR(A[(x+1)%5][y].NOT().AND(A[(x+2)%5][y]))
        end for
    end for
    return B
end function
SHAKE128.keccak_f = function
    for n in range(0, 23)
        self.theta(self.state)
        self.state = self.rho_pi(self.state)
        self.state = self.chi(self.state)
        self.iota(self.state, n)
    end for
end function
SHAKE128.shake_pad = function(msg, rate)
    out = msg[:]
    out.push(31)
    while (out.len % rate) != (rate - 1)
        out.push(0)
    end while
    out.push(128)
    return out
end function
SHAKE128.xor_byte_into_lane = function(lane, byte, offset)
    XOR = function(a, b)
        return bitXor(floor(a / 65536), floor(b / 65536)) * 65536 + bitXor(a % 65536, b % 65536)
    end function
    if offset < 4 then
        lane.lo = XOR(lane.lo, (byte * (2 ^ (8 * offset))) % 4294967296)
    else
        lane.hi = XOR(lane.hi, (byte * (2 ^ (8 * (offset - 4)))) % 4294967296)
    end if
end function
SHAKE128.absorb = function(data, rate)
    for block_start in range(0, data.len - rate, rate)
        block = data[block_start:block_start + rate]
        for j in block.indexes
            b = block[j]
            lane = floor(j / 8)
            offset = j % 8
            x = lane % 5
            y = floor(lane / 5)
            self.xor_byte_into_lane(self.state[x][y], b, offset)
        end for
        self.keccak_f
    end for
end function
SHAKE128.get_byte_from_lane = function(lane, offset)
    if offset < 4 then
        return floor(lane.lo / (2 ^ (8 * offset))) % 256
    else
        return floor(lane.hi / (2 ^ (8 * (offset - 4)))) % 256
    end if
end function
SHAKE128.squeeze = function(outlen)
    out = []
    while out.len < outlen
        if self.offset == self.rate then
            self.keccak_f
            self.offset = 0
        end if
        lane = floor(self.offset / 8)
        byte_off = self.offset % 8
        x = lane % 5
        y = floor(lane / 5)
        out.push(self.get_byte_from_lane(self.state[x][y], byte_off))
        self.offset = self.offset + 1
    end while
    return out
end function
SHAKE128.init = function(msg)
    shake128 = new SHAKE128
    shake128.rate = 168
    shake128.offset = 0
    shake128.state = [[0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]
    for i in range(0, 4)
        for j in range(0, 4)
            shake128.state[i][j] = uint64.init(0, 0)
        end for
    end for
    padded = shake128.shake_pad(msg, shake128.rate)
    shake128.absorb(padded, shake128.rate)
    return shake128
end function

bytes2hex = function(bytes)
    hex = []
    wordlist = "0123456789abcdef"
    for byte in bytes
        if byte >= 256 then return null
        push(hex, wordlist[floor(byte / len(wordlist))] + wordlist[byte % len(wordlist)])
    end for
    hex = join(hex, "")
    return hex
end function
shake128 = function(msg, outlen = 64)
    msg = values(msg)
    for i in indexes(msg)
        msg[i] = code(msg[i])
    end for
    shake = SHAKE128.init(msg)
    return bytes2hex(shake.squeeze(outlen))
end function
