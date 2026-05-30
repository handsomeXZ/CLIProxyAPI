package helps

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

var opencodeSessionIDPattern = regexp.MustCompile(`^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$`)

func TestApplyAffinityRewriteStableForSameAuthAndSession(t *testing.T) {
	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret"}}
	auth := &cliproxyauth.Auth{ID: "auth-1"}

	first := http.Header{}
	ApplyAffinityRewrite(first, cfg, auth, http.Header{"X-Session-Affinity": []string{"session-1"}})
	second := http.Header{}
	ApplyAffinityRewrite(second, cfg, auth, http.Header{"X-Session-Affinity": []string{"session-1"}})

	if first.Get("x-session-affinity") == "" {
		t.Fatal("expected rewritten x-session-affinity")
	}
	if first.Get("x-session-affinity") != second.Get("x-session-affinity") {
		t.Fatalf("rewritten affinity is not stable: %q != %q", first.Get("x-session-affinity"), second.Get("x-session-affinity"))
	}
}

func TestApplyAffinityRewriteUsesOpenCodeSessionShape(t *testing.T) {
	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret"}}
	target := http.Header{}

	ApplyAffinityRewrite(target, cfg, &cliproxyauth.Auth{ID: "auth-1"}, http.Header{"X-Session-Affinity": []string{"ses_000000000001ABCDEFGHIJKLMN"}})

	if got := target.Get("x-session-affinity"); !opencodeSessionIDPattern.MatchString(got) {
		t.Fatalf("rewritten affinity = %q, want OpenCode-like ses_<12hex><14base62>", got)
	}
}

func TestApplyAffinityRewriteLogsOriginalAndRewrittenID(t *testing.T) {
	previousLevel := log.GetLevel()
	previousHooks := cloneLogHooks(log.StandardLogger().Hooks)
	log.SetLevel(log.InfoLevel)
	hook := test.NewLocal(log.StandardLogger())
	t.Cleanup(func() {
		hook.Reset()
		log.StandardLogger().ReplaceHooks(previousHooks)
		log.SetLevel(previousLevel)
	})

	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret"}}
	target := http.Header{}

	ApplyAffinityRewrite(target, cfg, &cliproxyauth.Auth{ID: "auth-1"}, http.Header{"X-Session-Affinity": []string{"session-1"}})

	rewritten := target.Get("x-session-affinity")
	for _, entry := range hook.AllEntries() {
		if entry.Level != log.InfoLevel || entry.Message != "affinity rewrite: session affinity id rewritten" {
			continue
		}
		if entry.Data["original_id"] != "session-1" {
			t.Fatalf("original_id = %v, want session-1", entry.Data["original_id"])
		}
		if entry.Data["rewritten_id"] != rewritten {
			t.Fatalf("rewritten_id = %v, want %s", entry.Data["rewritten_id"], rewritten)
		}
		return
	}
	t.Fatalf("expected affinity rewrite log entry, got %#v", hook.AllEntries())
}

func TestApplyAffinityRewriteIsolatesCredentials(t *testing.T) {
	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret"}}
	source := http.Header{"X-Session-Affinity": []string{"session-1"}}

	first := http.Header{}
	ApplyAffinityRewrite(first, cfg, &cliproxyauth.Auth{ID: "auth-1"}, source)
	second := http.Header{}
	ApplyAffinityRewrite(second, cfg, &cliproxyauth.Auth{ID: "auth-2"}, source)

	if first.Get("x-session-affinity") == second.Get("x-session-affinity") {
		t.Fatalf("different credentials produced same affinity: %q", first.Get("x-session-affinity"))
	}
}

func TestApplyAffinityRewriteUpdatesExistingAndSourceHeaders(t *testing.T) {
	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret"}}
	target := http.Header{}
	lowerSessionID := "session_id"
	canonicalSessionID := "Session_id"
	target[lowerSessionID] = []string{"generated-cache"}
	source := http.Header{"X-Session-Affinity": []string{"session-1"}}

	ApplyAffinityRewrite(target, cfg, &cliproxyauth.Auth{ID: "auth-1"}, source)

	rewritten := target.Get("x-session-affinity")
	if rewritten == "" {
		t.Fatal("expected source x-session-affinity to be added to target")
	}
	if got := headerValue(target, "session_id"); got != rewritten {
		t.Fatalf("expected existing session_id to match rewritten affinity, got %q and %q", got, rewritten)
	}
	if _, ok := target[lowerSessionID]; !ok {
		t.Fatalf("expected lowercase session_id key to be preserved, got %#v", target)
	}
	if _, ok := target[canonicalSessionID]; ok {
		t.Fatalf("expected canonical Session_id key to be absent, got %#v", target)
	}
}

func TestApplyAffinityRewritePreservesSourceHeaderCase(t *testing.T) {
	cfg := &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true, Secret: "test-secret", Headers: []string{"session_id"}}}
	target := http.Header{}
	source := http.Header{}
	lowerSessionID := "session_id"
	canonicalSessionID := "Session_id"
	source[lowerSessionID] = []string{"session-1"}

	ApplyAffinityRewrite(target, cfg, &cliproxyauth.Auth{ID: "auth-1"}, source)

	if got := headerValue(target, "session_id"); got == "" || got == "session-1" {
		t.Fatalf("expected source session_id to be rewritten, got %q", got)
	}
	if _, ok := target[lowerSessionID]; !ok {
		t.Fatalf("expected source lowercase session_id key to be preserved, got %#v", target)
	}
	if _, ok := target[canonicalSessionID]; ok {
		t.Fatalf("expected canonical Session_id key to be absent, got %#v", target)
	}
}

func TestApplyAffinityRewriteDisabledWithoutSecret(t *testing.T) {
	target := http.Header{"X-Session-Affinity": []string{"session-1"}}
	ApplyAffinityRewrite(target, &config.Config{AffinityRewrite: config.AffinityRewriteConfig{Enabled: true}}, &cliproxyauth.Auth{ID: "auth-1"})

	if target.Get("x-session-affinity") != "session-1" {
		t.Fatalf("expected affinity to remain unchanged without secret, got %q", target.Get("x-session-affinity"))
	}
}

func cloneLogHooks(hooks log.LevelHooks) log.LevelHooks {
	clone := make(log.LevelHooks, len(hooks))
	for level, levelHooks := range hooks {
		clone[level] = append([]log.Hook(nil), levelHooks...)
	}
	return clone
}
