package helps

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var defaultAffinityRewriteHeaders = []string{"x-session-affinity", "session-id", "session_id"}

const affinityRewriteBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func ApplyAffinityRewrite(headers http.Header, cfg *config.Config, auth *cliproxyauth.Auth, sources ...http.Header) {
	if headers == nil || cfg == nil || !cfg.AffinityRewrite.Enabled {
		return
	}
	secret := strings.TrimSpace(cfg.AffinityRewrite.Secret)
	if secret == "" {
		return
	}
	scope := affinityCredentialScope(auth)
	if scope == "" {
		return
	}
	names := affinityHeaderNames(cfg.AffinityRewrite.Headers)
	original := firstAffinityValue(names, append(sources, headers)...)
	if original == "" {
		return
	}
	replacement := affinityRewriteValue(secret, cfg.AffinityRewrite.Prefix, scope, original)
	applied := false
	for _, name := range names {
		if hasHeaderValue(headers, name) || anySourceHasHeaderValue(sources, name) {
			setAffinityHeader(headers, name, replacement, sources)
			applied = true
		}
	}
	if applied {
		log.WithFields(log.Fields{
			"original_id":  original,
			"rewritten_id": replacement,
		}).Infof("affinity rewrite: session affinity id rewritten original_id=%s rewritten_id=%s", original, replacement)
	}
}

func affinityHeaderNames(configured []string) []string {
	if len(configured) == 0 {
		return defaultAffinityRewriteHeaders
	}
	return configured
}

func firstAffinityValue(names []string, headers ...http.Header) string {
	for _, source := range headers {
		for _, name := range names {
			if value := headerValue(source, name); value != "" {
				return value
			}
		}
	}
	return ""
}

func anySourceHasHeaderValue(sources []http.Header, name string) bool {
	for _, source := range sources {
		if hasHeaderValue(source, name) {
			return true
		}
	}
	return false
}

func hasHeaderValue(headers http.Header, name string) bool {
	return headerValue(headers, name) != ""
}

func headerValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	if value := strings.TrimSpace(headers.Get(name)); value != "" {
		return value
	}
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func setAffinityHeader(headers http.Header, name string, value string, sources []http.Header) {
	key := headerKey(headers, name)
	if key == "" {
		for _, source := range sources {
			if key = headerKey(source, name); key != "" {
				break
			}
		}
	}
	if key == "" {
		key = strings.TrimSpace(name)
	}
	if key == "" {
		return
	}
	deleteHeader(headers, key)
	headers[key] = []string{value}
}

func headerKey(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	for key := range headers {
		if strings.EqualFold(key, name) {
			return key
		}
	}
	return ""
}

func deleteHeader(headers http.Header, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func affinityCredentialScope(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if value := strings.TrimSpace(auth.ID); value != "" {
		return "id:" + value
	}
	if value := strings.TrimSpace(auth.Index); value != "" {
		return "index:" + value
	}
	parts := []string{strings.TrimSpace(auth.Provider), strings.TrimSpace(auth.Prefix), strings.TrimSpace(auth.ProxyURL)}
	if auth.Attributes != nil {
		parts = append(parts, strings.TrimSpace(auth.Attributes["base_url"]), strings.TrimSpace(auth.Attributes["api_key"]))
	}
	if strings.TrimSpace(strings.Join(parts, "")) == "" {
		return ""
	}
	return "fallback:" + strings.Join(parts, "\x00")
}

func affinityRewriteValue(secret string, prefix string, scope string, original string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "_-")
	if prefix == "" {
		prefix = "ses"
	}
	digest := hmacDigest(secret, "affinity\x00"+scope+"\x00"+original)
	return prefix + "_" + hex.EncodeToString(digest[:6]) + base62FromBytes(digest[6:], 14)
}

func hmacDigest(secret string, value string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func base62FromBytes(input []byte, length int) string {
	var out strings.Builder
	out.Grow(length)
	for i := range length {
		out.WriteByte(affinityRewriteBase62[int(input[i%len(input)])%len(affinityRewriteBase62)])
	}
	return out.String()
}
