package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"secretmgr/internal/store"
	"secretmgr/internal/tui"
)

func main() {
	st, err := store.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "store init error:", err)
		os.Exit(1)
	}

	p := tea.NewProgram(tui.NewModel(st), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
