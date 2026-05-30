package config

import "testing"

func TestParseConfigBytesAffinityRewrite(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte(`
affinity-rewrite:
  enabled: true
  secret: "  test-secret  "
  prefix: "  oc  "
  headers:
    - " x-session-affinity "
    - "Session-ID"
    - "session-id"
`))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if !cfg.AffinityRewrite.Enabled {
		t.Fatal("expected affinity rewrite to be enabled")
	}
	if cfg.AffinityRewrite.Secret != "test-secret" {
		t.Fatalf("secret = %q", cfg.AffinityRewrite.Secret)
	}
	if cfg.AffinityRewrite.Prefix != "oc" {
		t.Fatalf("prefix = %q", cfg.AffinityRewrite.Prefix)
	}
	if len(cfg.AffinityRewrite.Headers) != 2 {
		t.Fatalf("headers = %#v, want 2 entries", cfg.AffinityRewrite.Headers)
	}
	if cfg.AffinityRewrite.Headers[0] != "x-session-affinity" || cfg.AffinityRewrite.Headers[1] != "Session-ID" {
		t.Fatalf("headers = %#v", cfg.AffinityRewrite.Headers)
	}
}
