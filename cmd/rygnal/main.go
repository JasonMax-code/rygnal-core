package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Rygnal/rygnal-core/internal/cli"
)

func main() {
	os.Exit(run(cli.Execute, os.Stderr))
}

func run(execute func() error, stderr io.Writer) int {
	if err := execute(); err != nil {
		if code, ok := cli.ExitCode(err); ok {
			return code
		}

		fmt.Fprintln(stderr, "Error:", err)
		return 1
	}

	return 0
}
