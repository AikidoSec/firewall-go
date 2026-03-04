package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SelectItem struct {
	Name        string
	Description string
	selected    bool
	Locked      bool
}

type multiSelectModel struct {
	title    string
	subtitle string
	items    []SelectItem
	cursor   int
	done     bool
	aborted  bool
}

func (m *multiSelectModel) Init() tea.Cmd {
	return nil
}

// optionalIndices returns the indices of non-locked items.
func (m *multiSelectModel) optionalIndices() []int {
	var indices []int
	for i, item := range m.items {
		if !item.Locked {
			indices = append(indices, i)
		}
	}
	return indices
}

func (m *multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		optional := m.optionalIndices()
		// Find current position within optional items
		pos := 0
		for i, idx := range optional {
			if idx == m.cursor {
				pos = i
				break
			}
		}

		switch keyMsg.String() {
		case "up", "k":
			if pos > 0 {
				m.cursor = optional[pos-1]
			}
		case "down", "j":
			if pos < len(optional)-1 {
				m.cursor = optional[pos+1]
			}
		case " ":
			if m.cursor < len(m.items) {
				m.items[m.cursor].selected = !m.items[m.cursor].selected
			}
		case "enter":
			m.done = true
			return m, tea.Quit
		case "q", "esc", "ctrl+c":
			m.aborted = true
			return m, tea.Quit
		}
	}
	return m, nil
}

var accentColor = lipgloss.Color("#6551f3")

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	subtitleStyle = lipgloss.NewStyle()
	descStyle     = lipgloss.NewStyle().Faint(true)
	helpStyle     = lipgloss.NewStyle().Faint(true)
)

func (m *multiSelectModel) View() string {
	if m.done || m.aborted {
		return ""
	}

	var sb strings.Builder

	sb.WriteString(titleStyle.Render(m.title))
	sb.WriteString("\n")
	if m.subtitle != "" {
		sb.WriteString(subtitleStyle.Render(m.subtitle))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")

	// Separate optional and locked items
	var optional, locked []int
	for i, item := range m.items {
		if item.Locked {
			locked = append(locked, i)
		} else {
			optional = append(optional, i)
		}
	}

	for _, i := range locked {
		sb.WriteString(m.renderItem(i))
		sb.WriteString("\n")
	}

	if len(locked) > 0 && len(optional) > 0 {
		sb.WriteString("  ---\n")
	}

	for _, i := range optional {
		sb.WriteString(m.renderItem(i))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(helpStyle.Render("  space select  /  enter confirm  /  q quit"))
	sb.WriteString("\n")

	return lipgloss.NewStyle().PaddingLeft(1).Render(sb.String())
}

var (
	accentStyle   = lipgloss.NewStyle().Foreground(accentColor)
	checkboxStyle = lipgloss.NewStyle().Foreground(accentColor)
)

func (m *multiSelectModel) renderItem(index int) string {
	item := m.items[index]

	cursor := "  "
	if index == m.cursor {
		cursor = accentStyle.Render("> ")
	}

	checkbox := "[ ]"
	if item.selected || item.Locked {
		checkbox = checkboxStyle.Render("[x]")
	}

	name := item.Name
	desc := ""
	if item.Description != "" {
		desc = "  " + descStyle.Render(item.Description)
	}

	if item.Locked {
		return "  [x] " + item.Name + desc
	}
	if index == m.cursor {
		return cursor + checkbox + " " + lipgloss.NewStyle().Bold(true).Render(name) + desc
	}
	return cursor + checkbox + " " + name + desc
}

func newMultiSelectModel(title, subtitle string, items []SelectItem) *multiSelectModel {
	cursor := 0
	for i, item := range items {
		if !item.Locked {
			cursor = i
			break
		}
	}
	return &multiSelectModel{
		title:    title,
		subtitle: subtitle,
		items:    items,
		cursor:   cursor,
	}
}

func (m *multiSelectModel) selectedItems() []string {
	var selected []string
	for _, item := range m.items {
		if item.selected && !item.Locked {
			selected = append(selected, item.Name)
		}
	}
	return selected
}

func RunMultiSelect(title, subtitle string, items []SelectItem) ([]string, error) {
	m := newMultiSelectModel(title, subtitle, items)

	p := tea.NewProgram(m)
	result, err := p.Run()
	if err != nil {
		return nil, err
	}

	final := result.(*multiSelectModel)
	if final.aborted {
		return nil, fmt.Errorf("selection aborted")
	}

	return final.selectedItems(), nil
}
