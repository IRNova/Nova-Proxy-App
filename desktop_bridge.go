//go:build windows && desktop

package main

import (
	"fmt"
	"os"

	"github.com/TheCanniball/CipherGate/desktop"
	"github.com/TheCanniball/CipherGate/src/core"
)

func runDesktop(cfg *core.Config) {
	fmt.Fprintln(os.Stderr, "starting ciphergate desktop...")
	desktop.Run(cfg)
}
