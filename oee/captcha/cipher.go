package captcha

// Cipher — সব version-এর interface
type Cipher interface {
	Encrypt(secret, text string, startAt, length int) (string, error)
	Decrypt(secret, text string, startAt, length int) (string, error)
}

// registry — config.version → Cipher
//
// JS-এর AH mapping হুবহু:
//   AH = { 1:p1, 2:L1, 3:i4, 4:S4, 5:V4, 6:d2, 7:N2, 8:Y2, 9:v5, 10:B5 }
var registry = map[int]Cipher{
	1:  makeCipherFromKS(v1Keystream),
	2:  makeCipherFromKS(v2Keystream),
	3:  makeCipherFromKS(v3Keystream),
	4:  makeCipherFromKS(v4Keystream),
	5:  makeCipherFromKS(v5Keystream),
	6:  makeCipherFromKS(v6Keystream),
	7:  makeCipherFromKS(v7Keystream),
	8:  makeCipherFromKS(v8Keystream),
	9:  makeCipherFromKS(v9Keystream),
	10: makeCipherFromKS(v10Keystream),
}

// GetCipher — version → Cipher
func GetCipher(version int) (Cipher, error) {
	c, ok := registry[version]
	if !ok {
		return nil, ErrUnknownVersion
	}
	return c, nil
}

// AvailableVersions — debug
func AvailableVersions() []int {
	out := make([]int, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}
