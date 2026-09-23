// Package rid implements the recipient-parameter URL scheme shared by the
// gophish and evilginx engines of evilgophish.
//
// The scheme is deliberately not tied to a fixed parameter name so operators
// can obfuscate the tracking parameter via setup.sh/replace_rid.sh. A single
// canonical implementation lives here so both sides encode and decode the
// same format.
package rid

import (
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"math/rand"
	"net/url"
)

// RecipientParameter is the URL parameter that points to the result ID for a
// recipient. Operators may globally rename this via setup.sh.
const RecipientParameter = "user_id"

// GenRandomString returns a random string of the given length using upper and
// lower case letters.
func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

// GenRandomAlphanumString returns a random alphanumeric string of the given
// length.
func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

// CreatePhishUrl appends an encrypted recipient parameter to base_url. The
// value is an 8-character RC4 key followed by a base64url-encoded blob whose
// first byte is a checksum of the plaintext parameters.
//
// The evilginx engine decodes this value with DecodeParams; the two functions
// must stay in sync.
func CreatePhishUrl(base_url string, params *url.Values) string {
	var ret string = base_url
	if len(*params) > 0 {
		key_arg := RecipientParameter

		enc_key := GenRandomAlphanumString(8)
		dec_params := params.Encode()

		var crc byte
		for _, c := range dec_params {
			crc += byte(c)
		}

		c, _ := rc4.NewCipher([]byte(enc_key))
		enc_params := make([]byte, len(dec_params)+1)
		c.XORKeyStream(enc_params[1:], []byte(dec_params))
		enc_params[0] = crc

		key_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))
		ret += "?" + key_arg + "=" + key_val
	}
	return ret
}

// ErrNotEncrypted is returned by DecodeParams when the value does not look
// like an encrypted parameter blob.
var ErrNotEncrypted = errors.New("value is not an encrypted parameter blob")

// ErrChecksum is returned by DecodeParams when the integrity checksum stored
// in the value does not match the decoded parameters.
var ErrChecksum = errors.New("decoded parameter checksum mismatch")

// DecodeParams decodes a value produced by CreatePhishUrl back into the
// original parameters. The evilginx engine uses this when a victim follows a
// generated phishing URL; it must stay in sync with CreatePhishUrl.
func DecodeParams(v string) (url.Values, error) {
	if len(v) <= 8 {
		return nil, ErrNotEncrypted
	}
	enc_key := v[:8]
	enc_vals, err := base64.RawURLEncoding.DecodeString(v[8:])
	if err != nil {
		return nil, err
	}
	if len(enc_vals) < 1 {
		return nil, ErrNotEncrypted
	}
	dec_params := make([]byte, len(enc_vals)-1)
	c, _ := rc4.NewCipher([]byte(enc_key))
	c.XORKeyStream(dec_params, enc_vals[1:])

	var crc_chk byte
	for _, b := range dec_params {
		crc_chk += b
	}
	if enc_vals[0] != crc_chk {
		return nil, ErrChecksum
	}
	return url.ParseQuery(string(dec_params))
}