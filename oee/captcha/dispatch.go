// captcha/dispatch.go
package captcha

import "fmt"

// encryptByVersion — pure-Go implementations দিয়ে encrypt।
// JS runtime fail করলে বা unavailable হলে fallback।
func encryptByVersion(version int, secret, text string, startAt, length int) (string, error) {
	switch version {
	case 1:
		return v1{}.Encrypt(secret, text, startAt, length), nil
	case 2:
		return v2{}.Encrypt(secret, text, startAt, length), nil
	case 3:
		return v3{}.Encrypt(secret, text, startAt, length), nil
	case 4:
		return v4{}.Encrypt(secret, text, startAt, length), nil
	case 5:
		return v5{}.Encrypt(secret, text, startAt, length), nil
	case 6:
		return v6{}.Encrypt(secret, text, startAt, length), nil
	case 7:
		return v7{}.Encrypt(secret, text, startAt, length), nil
	case 8:
		return v8{}.Encrypt(secret, text, startAt, length), nil
	case 9:
		return v9{}.Encrypt(secret, text, startAt, length), nil
	case 10:
		return v10{}.Encrypt(secret, text, startAt, length), nil
	default:
		return "", fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
}

// decryptByVersion — pure-Go implementations দিয়ে decrypt।
func decryptByVersion(version int, secret, text string, startAt, length int) (string, error) {
	switch version {
	case 1:
		return v1{}.Decrypt(secret, text, startAt, length), nil
	case 2:
		return v2{}.Decrypt(secret, text, startAt, length), nil
	case 3:
		return v3{}.Decrypt(secret, text, startAt, length), nil
	case 4:
		return v4{}.Decrypt(secret, text, startAt, length), nil
	case 5:
		return v5{}.Decrypt(secret, text, startAt, length), nil
	case 6:
		return v6{}.Decrypt(secret, text, startAt, length), nil
	case 7:
		return v7{}.Decrypt(secret, text, startAt, length), nil
	case 8:
		return v8{}.Decrypt(secret, text, startAt, length), nil
	case 9:
		return v9{}.Decrypt(secret, text, startAt, length), nil
	case 10:
		return v10{}.Decrypt(secret, text, startAt, length), nil
	default:
		return "", fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
}
