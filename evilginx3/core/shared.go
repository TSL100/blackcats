package core

import (
	"hash/fnv"
	"strings"
)

func fnv32(b []byte) uint32 {
	h := fnv.New32a()
	h.Write(b)
	return h.Sum32()
}

func combineHost(sub string, domain string) string {
	if sub == "" {
		return domain
	}
	return sub + "." + domain
}

// stripHostPort removes a trailing ":port" from a hostname string when present.
// Used in port-tolerance mode so that incoming Host values like
// "tsl2.example.com:8443" match the bare configured hostname "tsl2.example.com".
// Safe to call on a bare hostname (returns it unchanged).
func stripHostPort(host string) string {
	if host == "" {
		return host
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func obfuscateDots(s string) string {
	return strings.Replace(s, ".", "[[d0t]]", -1)
}

func removeObfuscatedDots(s string) string {
	return strings.Replace(s, "[[d0t]]", ".", -1)
}

func stringExists(s string, sa []string) bool {
	for _, k := range sa {
		if s == k {
			return true
		}
	}
	return false
}

func intExists(i int, ia []int) bool {
	for _, k := range ia {
		if i == k {
			return true
		}
	}
	return false
}

func removeString(s string, sa []string) []string {
	for i, k := range sa {
		if s == k {
			return append(sa[:i], sa[i+1:]...)
		}
	}
	return sa
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		ml := maxLen
		pre := s[:ml/2-1]
		suf := s[len(s)-(ml/2-2):]
		return pre + "..." + suf
	}
	return s
}
