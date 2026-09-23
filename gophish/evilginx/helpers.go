// Package evilginx provides the gophish-side integration helpers for the
// evilginx engine. The recipient-parameter URL scheme is implemented once in
// evilgophish/shared/rid; the functions here are compatibility wrappers so
// existing callers keep working unchanged.
package evilginx

import (
	"net/url"

	"evilgophish/shared/rid"
)

// RecipientParameter is the URL parameter that points to the result ID for a recipient.
const RecipientParameter = rid.RecipientParameter

func GenRandomString(n int) string {
	return rid.GenRandomString(n)
}

func GenRandomAlphanumString(n int) string {
	return rid.GenRandomAlphanumString(n)
}

func CreatePhishUrl(base_url string, params *url.Values) string {
	return rid.CreatePhishUrl(base_url, params)
}