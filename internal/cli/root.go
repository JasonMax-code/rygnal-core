package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

const (
	productName = "rygnal"
	shortDesc   = "Rygnal is an AI Agent Guardrails platform"
	longDesc    = "An enterprise-grade runtime containment and safety gate layer for autonomous AI agents."
)

const (
	ExitCompleted        = 0
	ExitCommandFailed    = 1
	ExitBlocked          = 2
	ExitApprovalRequired = 3
	ExitTimedOut         = 4
	ExitCleanupFailed    = 5
)

type ExitError struct {
	Code int
}

func (err ExitError) Error() string {
	return fmt.Sprintf("exit code %d", err.Code)
}

func ExitCode(err error) (int, bool) {
	var exitErr ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code, true
	}

	return 0, false
}

// Execute runs the production CLI entrypoint.
func Execute() error {
	return NewRootCommand().Execute()
}

// NewRootCommand constructs the root command.
//
// It is intentionally exported for tests so command behavior can be verified
// without mutating global Cobra state.
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           productName,
		Short:         shortDesc,
		Long:          longDesc,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newAuditCmd())

	return rootCmd
}
