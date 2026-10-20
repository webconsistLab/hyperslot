package captcha

import "fmt"

// VersionName returns a human-readable name for a captcha version number.
// Version numbers map 1:1 to the v1..v10 keystream implementations.
func VersionName(v int) string {
	switch v {
	case 1:
		return "v1 (ChaCha quarter-round + RC4 alphabet)"
	case 2:
		return "v2 (LCG imul + 3-bit state)"
	case 3:
		return "v3 (64-cell XOR shift)"
	case 4:
		return "v4 (RC4 KSA+PRGA, 64-symbol)"
	case 5:
		return "v5 (Fibonacci 3-LFSR 16/17/24)"
	case 6:
		return "v6 (polynomial rolling hash)"
	case 7:
		return "v7 (RC4 sbox, reverse-slice)"
	case 8:
		return "v8 (LCG imul+add, top 16 bits)"
	case 9:
		return "v9 (logistic map 3.99)"
	case 10:
		return "v10 (modular exponent mod 1000036000099)"
	default:
		return fmt.Sprintf("unknown (v%d)", v)
	}
}
