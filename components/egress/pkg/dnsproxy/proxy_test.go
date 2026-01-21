package dnsproxy

import (
	"testing"

	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

func TestProxyUpdatePolicy(t *testing.T) {
	proxy, err := New(nil, "127.0.0.1:15353")
	if err != nil {
		t.Fatalf("init proxy: %v", err)
	}

	if proxy.CurrentPolicy() != nil {
		t.Fatalf("expected initial allow-all (nil policy)")
	}

	pol, err := policy.ParsePolicy(`{"default_action":"deny","egress":[{"action":"allow","target":"example.com"}]}`)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	proxy.UpdatePolicy(pol)
	if proxy.CurrentPolicy() == nil {
		t.Fatalf("expected policy after update")
	}
	if got := proxy.CurrentPolicy().Evaluate("example.com."); got != policy.ActionAllow {
		t.Fatalf("policy evaluation mismatch, want allow got %s", got)
	}

	proxy.UpdatePolicy(nil)
	if proxy.CurrentPolicy() != nil {
		t.Fatalf("expected allow-all after clearing policy")
	}
}
