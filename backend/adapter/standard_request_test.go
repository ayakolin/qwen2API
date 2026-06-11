package adapter

import (
	"strings"
	"testing"
)

func TestCompactToolResultBodyShortPassthrough(t *testing.T) {
	body := "short result"
	if got := compactToolResultBody(body, 8000); got != body {
		t.Fatalf("short body mutated: %q", got)
	}
}

func TestCompactToolResultBodyKeepsHeadAndTail(t *testing.T) {
	head := strings.Repeat("H", 4000)
	tail := strings.Repeat("T", 4000)
	body := head + strings.Repeat("M", 4000) + tail
	got := compactToolResultBody(body, 8000)

	if len(got) >= len(body) {
		t.Fatalf("expected compaction, got len %d >= %d", len(got), len(body))
	}
	if !strings.HasPrefix(got, "HHH") {
		t.Fatalf("expected head preserved, got prefix %q", got[:10])
	}
	if !strings.HasSuffix(got, "TTT") {
		t.Fatalf("expected tail preserved, got suffix %q", got[len(got)-10:])
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
}

func TestRenderToolResultIncludesID(t *testing.T) {
	got := renderToolResult("call_1", "ok")
	if !strings.Contains(got, "id=call_1") {
		t.Fatalf("missing id: %q", got)
	}
	if !strings.Contains(got, "[Tool Result") || !strings.Contains(got, "[/Tool Result]") {
		t.Fatalf("missing markers: %q", got)
	}
}
