package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Rygnal/rygnal-core/internal/cli"
)

func TestRunReturnsTypedExitCodeWithoutErrorNoise(t *testing.T) {
	var stderr bytes.Buffer

	code := run(func() error {
		return cli.ExitError{Code: cli.ExitApprovalRequired}
	}, &stderr)

	if code != cli.ExitApprovalRequired {
		t.Fatalf("expected exit code %d, got %d", cli.ExitApprovalRequired, code)
	}

	if stderr.String() != "" {
		t.Fatalf("typed exit errors should not print generic error text, got %q", stderr.String())
	}
}

func TestRunReturnsOneForOrdinaryErrors(t *testing.T) {
	var stderr bytes.Buffer

	code := run(func() error {
		return errors.New("ordinary failure")
	}, &stderr)

	if code != 1 {
		t.Fatalf("expected generic exit code 1, got %d", code)
	}

	if !strings.Contains(stderr.String(), "Error: ordinary failure") {
		t.Fatalf("expected generic error text, got %q", stderr.String())
	}
}

func TestRunReturnsZeroOnSuccess(t *testing.T) {
	var stderr bytes.Buffer

	code := run(func() error {
		return nil
	}, &stderr)

	if code != 0 {
		t.Fatalf("expected success exit code 0, got %d", code)
	}

	if stderr.String() != "" {
		t.Fatalf("success should not write stderr, got %q", stderr.String())
	}
}
