package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestModel() *multiSelectModel {
	return &multiSelectModel{
		title:    "Test",
		subtitle: "Test subtitle",
		items: []SelectItem{
			{Name: "a", Description: "Option A", selected: false, Locked: false},
			{Name: "b", Description: "Option B", selected: false, Locked: false},
			{Name: "c", Description: "Always included", selected: false, Locked: true},
		},
	}
}

func key(k string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

func specialKey(k tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: k}
}

func TestMultiSelect_ToggleOptionalItem(t *testing.T) {
	m := newTestModel()

	m.Update(key(" "))
	assert.True(t, m.items[0].selected)

	m.Update(key(" "))
	assert.False(t, m.items[0].selected)
}

func TestMultiSelect_CannotToggleLockedItem(t *testing.T) {
	m := newTestModel()
	m.cursor = 2 // locked item

	m.Update(key(" "))
	assert.False(t, m.items[2].selected, "locked item should not be toggled")
}

func TestMultiSelect_EnterSetsDone(t *testing.T) {
	m := newTestModel()

	_, cmd := m.Update(specialKey(tea.KeyEnter))
	assert.True(t, m.done)
	assert.False(t, m.aborted)
	require.NotNil(t, cmd)
}

func TestMultiSelect_EscSetsAborted(t *testing.T) {
	m := newTestModel()

	_, cmd := m.Update(specialKey(tea.KeyEsc))
	assert.True(t, m.aborted)
	assert.False(t, m.done)
	require.NotNil(t, cmd)
}

func TestMultiSelect_QSetsAborted(t *testing.T) {
	m := newTestModel()

	_, cmd := m.Update(key("q"))
	assert.True(t, m.aborted)
	require.NotNil(t, cmd)
}

func TestMultiSelect_NavigationBounds(t *testing.T) {
	m := newTestModel()
	assert.Equal(t, 0, m.cursor)

	// Can't go above 0
	m.Update(key("k"))
	assert.Equal(t, 0, m.cursor)

	// Move to last item
	m.Update(key("j"))
	m.Update(key("j"))
	assert.Equal(t, 2, m.cursor)

	// Can't go below last item
	m.Update(key("j"))
	assert.Equal(t, 2, m.cursor)
}

func TestMultiSelect_ArrowKeys(t *testing.T) {
	m := newTestModel()

	m.Update(specialKey(tea.KeyDown))
	assert.Equal(t, 1, m.cursor)

	m.Update(specialKey(tea.KeyUp))
	assert.Equal(t, 0, m.cursor)
}

func TestMultiSelect_SelectedItems(t *testing.T) {
	m := newTestModel()

	// Select first item
	m.Update(key(" "))

	// Move to second and select
	m.Update(key("j"))
	m.Update(key(" "))

	// Confirm
	m.Update(specialKey(tea.KeyEnter))

	// Collect selected non-locked items
	var selected []string
	for _, item := range m.items {
		if item.selected && !item.Locked {
			selected = append(selected, item.Name)
		}
	}
	assert.Equal(t, []string{"a", "b"}, selected)
}

func TestMultiSelect_ViewShowsSeparator(t *testing.T) {
	m := newTestModel()
	view := m.View()
	assert.Contains(t, view, "---")
}

func TestMultiSelect_ViewShowsTitle(t *testing.T) {
	m := newTestModel()
	view := m.View()
	assert.Contains(t, view, "Test")
	assert.Contains(t, view, "Test subtitle")
}

func TestMultiSelect_ViewShowsHelpBar(t *testing.T) {
	m := newTestModel()
	view := m.View()
	assert.Contains(t, view, "space select")
	assert.Contains(t, view, "enter confirm")
	assert.Contains(t, view, "q quit")
}

func TestMultiSelect_ViewEmptyWhenDone(t *testing.T) {
	m := newTestModel()
	m.done = true
	assert.Equal(t, "", m.View())
}

func TestMultiSelect_ViewEmptyWhenAborted(t *testing.T) {
	m := newTestModel()
	m.aborted = true
	assert.Equal(t, "", m.View())
}

func TestMultiSelect_NoLockedItems(t *testing.T) {
	m := &multiSelectModel{
		title: "Test",
		items: []SelectItem{
			{Name: "a", Description: "Option A"},
			{Name: "b", Description: "Option B"},
		},
	}
	view := m.View()
	assert.NotContains(t, view, "---")
}

func TestMultiSelect_NoOptionalItems(t *testing.T) {
	m := &multiSelectModel{
		title: "Test",
		items: []SelectItem{
			{Name: "a", Description: "Always", Locked: true},
		},
	}
	view := m.View()
	assert.NotContains(t, view, "---")
}
