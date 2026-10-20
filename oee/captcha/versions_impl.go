package captcha

import "math"

// ─────────────────────────────────────────────
// v1 — p1: ChaCha-inspired quarter-round + RC4-alphabet
// JS: r1(seed, len) + o1/s1
// ─────────────────────────────────────────────
type v1 struct{}

func (v1) Encrypt(secret, text string, startAt, length int) string {
	ks := v1Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v1) Decrypt(secret, text string, startAt, length int) string {
	ks := v1Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v1Quarter(e, t, n, r uint32) (uint32, uint32, uint32, uint32) {
	e += t
	r ^= e
	r = r<<16 | r>>16
	n += r
	t ^= n
	t = t<<12 | t>>20
	e += t
	r ^= e
	r = r<<8 | r>>24
	n += r
	t ^= n
	t = t<<7 | t>>25
	return e, t, n, r
}

func v1Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var st [16]uint32
	for i := 0; i < len(secret); i++ {
		st[i%16] = (st[i%16] + uint32(secret[i])) & 0xFFFFFFFF
	}
	st[15] = uint32(length)

	out := make([]int, 0, length)
	blocks := (length + 3) / 4
	for b := 0; b < blocks; b++ {
		st[14] = uint32(b)
		s := st
		for t := 0; t < 10; t++ {
			s[0], s[4], s[8], s[12] = v1Quarter(s[0], s[4], s[8], s[12])
			s[1], s[5], s[9], s[13] = v1Quarter(s[1], s[5], s[9], s[13])
			s[2], s[6], s[10], s[14] = v1Quarter(s[2], s[6], s[10], s[14])
			s[3], s[7], s[11], s[15] = v1Quarter(s[3], s[7], s[11], s[15])
		}
		for i := 0; i < 4; i++ {
			out = append(out, int(s[i]%uint32(AlphaLen)))
		}
	}
	return out[:length]
}

// ─────────────────────────────────────────────
// v2 — L1: imul LCG + 3-bit state
// ─────────────────────────────────────────────
type v2 struct{}

func (v2) Encrypt(secret, text string, startAt, length int) string {
	ks := v2Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v2) Decrypt(secret, text string, startAt, length int) string {
	ks := v2Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

// JS: w1(seed, len) + A1(a,b) then O1/N1
func v2Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var st uint32
	for i := 0; i < len(secret); i++ {
		st = (st + uint32(secret[i])*uint32(i+1)) & 0xFFFFFFFF
	}
	bits := make([]int, length)
	for i := 0; i < length; i++ {
		st = uint32(int32(st)*1103515245+12345) & 0xFFFFFFFF
		bits[i] = int(st & 7)
	}
	return bits
}

// ─────────────────────────────────────────────
// v3 — i4: 64-cell XOR shift (cell = f(a, b))
// ─────────────────────────────────────────────
type v3 struct{}

func (v3) Encrypt(secret, text string, startAt, length int) string {
	ks := v3Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v3) Decrypt(secret, text string, startAt, length int) string {
	ks := v3Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v3Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var st [64]uint8
	for i := 0; i < len(secret); i++ {
		st[i%64] ^= uint8(secret[i]) & 1
	}
	st[32] = 1
	out := make([]int, length)
	for p := 0; p < length; p++ {
		var next [64]uint8
		var t uint8
		for n := 0; n < 64; n++ {
			i := st[(n+63)%64]
			a := st[n]
			s := st[(n+1)%64]
			next[n] = i ^ (a | s)
			if n < 6 {
				t = t<<1 | next[n]
			}
		}
		st = next
		out[p] = int(t) % AlphaLen
	}
	return out
}

// ─────────────────────────────────────────────
// v4 — S4: classic RC4 KSA+PRGA on 64-symbol alphabet
// ─────────────────────────────────────────────
type v4 struct{}

func (v4) Encrypt(secret, text string, startAt, length int) string {
	ks := v4Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v4) Decrypt(secret, text string, startAt, length int) string {
	ks := v4Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v4Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var s [64]int
	for i := 0; i < 64; i++ {
		s[i] = i
	}
	var j int
	for i := 0; i < 64; i++ {
		j = (j + s[i] + int(secret[i%len(secret)])) % 64
		s[i], s[j] = s[j], s[i]
	}
	i, j := 0, 0
	out := make([]int, length)
	for k := 0; k < length; k++ {
		i = (i + 1) % 64
		j = (j + s[i]) % 64
		s[i], s[j] = s[j], s[i]
		out[k] = s[(s[i]+s[j])%64]
	}
	return out
}

// ─────────────────────────────────────────────
// v5 — V4: Fibonacci 3-LFSR (16/17/24 bit registers)
// ─────────────────────────────────────────────
type v5 struct{}

func (v5) Encrypt(secret, text string, startAt, length int) string {
	ks := v5Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v5) Decrypt(secret, text string, startAt, length int) string {
	ks := v5Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v5Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var a uint32 = 74565
	var c uint32 = 424090
	var u uint32 = 773615
	for i := 0; i < len(secret); i++ {
		ch := uint32(secret[i])
		a ^= ch | 1
		c ^= 1 | ch<<2
		u ^= ch<<4 | 1
	}
	out := make([]int, length)
	for p := 0; p < length; p++ {
		var v uint32
		for t := 0; t < 6; t++ {
			tb := ((a) ^ a>>2 ^ a>>3 ^ a>>5) & 1
			a = a>>1 | tb<<15
			cb := ((c) ^ c>>1 ^ c>>2 ^ c>>7) & 1
			c = c>>1 | cb<<16
			ub := ((u) ^ u>>1 ^ u>>2 ^ u>>22) & 1
			u = u>>1 | ub<<23
			bit := tb&cb ^ ^tb&ub
			v = v<<1 | bit
		}
		out[p] = int(v % uint32(AlphaLen))
	}
	return out
}

// ─────────────────────────────────────────────
// v6 — d2: polynomial rolling hash
// ─────────────────────────────────────────────
type v6 struct{}

func (v6) Encrypt(secret, text string, startAt, length int) string {
	ks := v6Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v6) Decrypt(secret, text string, startAt, length int) string {
	ks := v6Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v6Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	n := len(secret)
	if n < 3 {
		n = 3
	}
	d := make([]int, n)
	for i := 0; i < n; i++ {
		d[i] = (int(secret[i%len(secret)]) + i) % 67
	}
	out := make([]int, length)
	for p := 1; p <= length; p++ {
		var h, pw int64
		pw = 1
		for _, x := range d {
			h = (h + int64(x)*pw) % 67
			pw = pw * int64(p) % 67
		}
		out[p-1] = int(h % int64(AlphaLen))
	}
	return out
}

// ─────────────────────────────────────────────
// v7 — N2: RC4 sbox, reverse-slice
// ─────────────────────────────────────────────
type v7 struct{}

func (v7) Encrypt(secret, text string, startAt, length int) string {
	ks := v7Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v7) Decrypt(secret, text string, startAt, length int) string {
	ks := v7Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v7Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var s [64]int
	var inv [64]int
	for i := 0; i < 64; i++ {
		s[i] = i
	}
	var j int
	for i := 0; i < 64; i++ {
		j = (j + s[i] + int(secret[i%len(secret)])) % 64
		s[i], s[j] = s[j], s[i]
	}
	for i := 0; i < 64; i++ {
		inv[s[i]] = i
	}
	_ = inv // suppress unused
	out := make([]int, length)
	for i := 0; i < length; i++ {
		out[i] = s[i%64]
	}
	return out
}

// ─────────────────────────────────────────────
// v8 — Y2: imul+add LCG, top 16 bits
// ─────────────────────────────────────────────
type v8 struct{}

func (v8) Encrypt(secret, text string, startAt, length int) string {
	ks := v8Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v8) Decrypt(secret, text string, startAt, length int) string {
	ks := v8Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v8Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var s uint32 = 123456789
	for i := 0; i < len(secret); i++ {
		s = (s + uint32(secret[i])) & 0xFFFFFFFF
	}
	out := make([]int, length)
	l := uint32(1103515245)
	for i := 0; i < length; i++ {
		s = uint32(int32(s)*int32(l)+12345) & 0xFFFFFFFF
		l = l + s | 1
		out[i] = int(s>>16) % AlphaLen
	}
	return out
}

// ─────────────────────────────────────────────
// v9 — v5: logistic map 3.99·x·(1−x)
// ─────────────────────────────────────────────
type v9 struct{}

func (v9) Encrypt(secret, text string, startAt, length int) string {
	ks := v9Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v9) Decrypt(secret, text string, startAt, length int) string {
	ks := v9Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v9Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	x := 0.5
	for i := 0; i < len(secret); i++ {
		x = math.Mod(x+float64(secret[i])/256, 1.0)
	}
	if x == 0 {
		x = 0.5
	}
	out := make([]int, 0, length)
	for i := 0; i < length+100; i++ {
		x = 3.99 * x * (1 - x)
		if i >= 100 {
			out = append(out, int(math.Floor(10000000*x))%AlphaLen)
		}
	}
	return out
}

// ─────────────────────────────────────────────
// v10 — B5: modular exponent mod 1000036000099
// ─────────────────────────────────────────────
type v10 struct{}

const modPrime = int64(1000036000099)

func (v10) Encrypt(secret, text string, startAt, length int) string {
	ks := v10Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, +1)
}

func (v10) Decrypt(secret, text string, startAt, length int) string {
	ks := v10Keystream(secret, length)
	return applyKeystream(text, startAt, length, ks, -1)
}

func v10Keystream(secret string, length int) []int {
	if length <= 0 {
		return nil
	}
	var s int64 = 314159265
	for i := 0; i < len(secret); i++ {
		s = (s + int64(secret[i])*int64(i+1)) % modPrime
	}
	if s%2 == 0 {
		s++
	}
	out := make([]int, length)
	for i := 0; i < length; i++ {
		s = modMul(s, s, modPrime)
		out[i] = int(s % int64(AlphaLen))
	}
	return out
}

func modMul(a, b, m int64) int64 {
	var result int64
	a = a % m
	for b > 0 {
		if b&1 == 1 {
			result = (result + a) % m
		}
		a = (a + a) % m
		b >>= 1
	}
	return result
}
