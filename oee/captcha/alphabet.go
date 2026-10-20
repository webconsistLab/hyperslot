package captcha

import "errors"

var (
	ErrUnknownVersion = errors.New("captcha: unknown encrypt version")
	ErrEmptySecret    = errors.New("captcha: secret is empty")
	ErrEmptyToken     = errors.New("captcha: raw token is empty")
	ErrBadRange       = errors.New("captcha: invalid startAt/length")
)

// Alphabet — সব version-এ একই
const Alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
const AlphaLen = 64

// clipRange — JS-এর Math.max/min এর হুবহু
func clipRange(textLen, startAt, length int) (int, int) {
	s := startAt
	if s < 0 {
		s = 0
	}
	if s > textLen {
		s = textLen
	}
	rem := textLen - s
	if rem < 0 {
		rem = 0
	}
	l := length
	if l > rem {
		l = rem
	}
	if l < 0 {
		l = 0
	}
	return s, l
}

func idxByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// applyKeystream — সব version-এ একই forward/inverse
// mode = +1 (encrypt), -1 (decrypt)
func applyKeystream(text string, startAt, length int, ks []int, mode int) string {
	if len(text) == 0 || len(ks) == 0 {
		return text
	}
	s, l := clipRange(len(text), startAt, length)
	if l == 0 {
		return text
	}
	out := []byte(text)
	for i := 0; i < l; i++ {
		pos := s + i
		idx := idxByte(Alphabet, out[pos])
		if idx == -1 {
			continue
		}
		var newIdx int
		if mode > 0 {
			newIdx = ((idx+ks[i])%AlphaLen + AlphaLen) % AlphaLen
		} else {
			newIdx = ((idx-ks[i])%AlphaLen + AlphaLen) % AlphaLen
		}
		out[pos] = Alphabet[newIdx]
	}
	return string(out)
}

// KeystreamFn — প্রতিটি version-এর signature
type KeystreamFn func(secret string, length int) []int

// makeCipherFromKS — generic Encrypt/Decrypt builder
func makeCipherFromKS(ksFn KeystreamFn) Cipher {
	return &simpleCipher{ks: ksFn}
}

type simpleCipher struct {
	ks KeystreamFn
}

func (c *simpleCipher) Encrypt(secret, text string, startAt, length int) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}
	return applyKeystream(text, startAt, length, c.ks(secret, length), +1), nil
}

func (c *simpleCipher) Decrypt(secret, text string, startAt, length int) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}
	return applyKeystream(text, startAt, length, c.ks(secret, length), -1), nil
}
