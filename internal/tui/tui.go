package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func Run() error {
	m, err := newModel()
	if err != nil {
		return err
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
