package upstream

import "testing"

func TestSnapshotNormalizerDedupesCumulativeReasoning(t *testing.T) {
	var n SnapshotNormalizer
	steps := []struct {
		in   Event
		want string
	}{
		{Event{Type: "delta", Phase: "thinking_summary", Content: "Hello", ReasoningText: "Hello", ContentIsSnapshot: true}, "Hello"},
		{Event{Type: "delta", Phase: "thinking_summary", Content: "Hello world", ReasoningText: "Hello world", ContentIsSnapshot: true}, " world"},
		{Event{Type: "delta", Phase: "thinking_summary", Content: "Hello world!", ReasoningText: "Hello world!", ContentIsSnapshot: true}, "!"},
	}
	for i, step := range steps {
		got := n.Normalize(step.in)
		if got.Content != step.want {
			t.Fatalf("step %d: content = %q, want %q", i, got.Content, step.want)
		}
		if got.ReasoningText != step.want {
			t.Fatalf("step %d: reasoning = %q, want %q", i, got.ReasoningText, step.want)
		}
		if got.ContentIsSnapshot {
			t.Fatalf("step %d: ContentIsSnapshot should be cleared", i)
		}
	}
}

func TestSnapshotNormalizerResetsOnAnswerPhase(t *testing.T) {
	var n SnapshotNormalizer
	n.Normalize(Event{Type: "delta", Phase: "thinking_summary", Content: "thinking", ReasoningText: "thinking", ContentIsSnapshot: true})

	// An answer-phase event should pass through untouched and clear state.
	ans := n.Normalize(Event{Type: "delta", Phase: "answer", Content: "final answer"})
	if ans.Content != "final answer" {
		t.Fatalf("answer content mutated: %q", ans.Content)
	}

	// A fresh thinking snapshot should now emit in full again.
	got := n.Normalize(Event{Type: "delta", Phase: "thinking_summary", Content: "thinking", ReasoningText: "thinking", ContentIsSnapshot: true})
	if got.Content != "thinking" {
		t.Fatalf("after reset content = %q, want full snapshot", got.Content)
	}
}

func TestSnapshotNormalizerLeavesIncrementalDeltas(t *testing.T) {
	var n SnapshotNormalizer
	evt := Event{Type: "delta", Phase: "think", Content: "abc", ReasoningText: "abc", ContentIsSnapshot: false}
	got := n.Normalize(evt)
	if got.Content != "abc" {
		t.Fatalf("incremental delta mutated: %q", got.Content)
	}
}

func TestExtractReasoningSnapshotFlag(t *testing.T) {
	direct, isSnap := extractReasoning(map[string]any{"reasoning_content": "abc"}, nil)
	if direct != "abc" || isSnap {
		t.Fatalf("direct reasoning: got (%q, %v), want (abc, false)", direct, isSnap)
	}
	extra := map[string]any{"summary_thought": "full thought"}
	snap, isSnap := extractReasoning(map[string]any{}, extra)
	if snap != "full thought" || !isSnap {
		t.Fatalf("snapshot reasoning: got (%q, %v), want (full thought, true)", snap, isSnap)
	}
}
