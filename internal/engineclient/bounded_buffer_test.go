package engineclient

import (
	"strings"
	"testing"
)

func TestBoundedBufferKeepsSmallStderr(t *testing.T) {
	buf := newBoundedBuffer(64)

	if _, err := buf.Write([]byte("small stderr")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}

	if got := buf.String(); got != "small stderr" {
		t.Fatalf("unexpected stderr: %q", got)
	}

	if buf.Truncated() {
		t.Fatal("small stderr should not be marked truncated")
	}
}

func TestBoundedBufferTruncatesLargeStderr(t *testing.T) {
	buf := newBoundedBuffer(16)

	if _, err := buf.Write([]byte("0123456789abcdefEXTRA")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}

	got := buf.String()

	if !buf.Truncated() {
		t.Fatal("large stderr should be marked truncated")
	}

	if !strings.HasPrefix(got, "[stderr truncated]\n") {
		t.Fatalf("missing truncation marker: %q", got)
	}

	if !strings.HasSuffix(got, "56789abcdefEXTRA") {
		t.Fatalf("did not keep stderr tail: %q", got)
	}
}

func TestBoundedBufferTruncatesAcrossMultipleWrites(t *testing.T) {
	buf := newBoundedBuffer(10)

	_, _ = buf.Write([]byte("hello"))
	_, _ = buf.Write([]byte("world"))
	_, _ = buf.Write([]byte("12345"))

	got := buf.String()

	if !buf.Truncated() {
		t.Fatal("stderr should be marked truncated")
	}

	if !strings.HasSuffix(got, "world12345") {
		t.Fatalf("did not keep newest stderr bytes: %q", got)
	}
}
