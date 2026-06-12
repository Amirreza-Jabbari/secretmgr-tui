package tui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	seccrypto "secretmgr/internal/crypto"
	"secretmgr/internal/model"
	"secretmgr/internal/store"
)

type screen int

const (
	screenAuthSetup screen = iota
	screenAuthLogin
	screenDocs
	screenItems
)

type fieldKind int

const (
	fieldNone fieldKind = iota
	fieldAuthSetupPass1
	fieldAuthSetupPass2
	fieldAuthLoginPass
	fieldSearch
	fieldDocName
	fieldItemName
	fieldItemSecret
)

type modalKind int

const (
	modalNone modalKind = iota
	modalConfirmDeleteDoc
	modalConfirmDeleteItem
)

type viewMode int

const (
	modeDocs viewMode = iota
	modeItems
)

type Model struct {
	store *store.Store
	sess  *seccrypto.Session
	vault *model.Vault

	screen screen
	mode   viewMode

	width  int
	height int

	auth1 textinput.Model
	auth2 textinput.Model
	auth3 textinput.Model

	searchInput textinput.Model
	docInput    textinput.Model
	itemName    textinput.Model
	itemSecret  textinput.Model

	activeField fieldKind
	formTitle   string

	docsSelected  int
	itemsSelected int

	docsFilter  string
	itemsFilter string

	docsFiltered  []int
	itemsFiltered []int

	statusMsg string
	errMsg    string

	modal modalKind

	pendingDocIndex  int
	pendingItemIndex int

	quitting bool
}

func NewModel(s *store.Store) Model {
	m := Model{store: s}
	m.auth1 = makePasswordInput("Create password", "At least 8 characters")
	m.auth2 = makePasswordInput("Confirm password", "Repeat the same password")
	m.auth3 = makePasswordInput("Password", "Enter your password")
	m.searchInput = makeInput("Search", "Type to filter")
	m.docInput = makeInput("Document name", "Unique friendly name")
	m.itemName = makeInput("Item name", "For example: API key")
	m.itemSecret = makeInput("Secret value", "Sensitive content or secret")

	if s.Exists() {
		m.screen = screenAuthLogin
		m.activeField = fieldAuthLoginPass
		m.auth3.Focus()
	} else {
		m.screen = screenAuthSetup
		m.activeField = fieldAuthSetupPass1
		m.auth1.Focus()
	}

	m.rebuildDocFilter()
	m.rebuildItemFilter()
	m.setStatus("Ready")
	return m
}

func makeInput(prompt, placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.Placeholder = placeholder
	ti.CharLimit = 128
	ti.Width = 48
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("230"))
	ti.PlaceholderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	_ = prompt
	return ti
}

func makePasswordInput(prompt, placeholder string) textinput.Model {
	ti := makeInput(prompt, placeholder)

	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'

	return ti
}

func (m Model) Init() tea.Cmd { return textinput.Blink }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if m.quitting {
			return m, tea.Quit
		}

		if m.activeField == fieldDocName || m.activeField == fieldItemName || m.activeField == fieldItemSecret {
			return m.updateForm(msg)
		}
		if m.activeField == fieldSearch {
			return m.updateSearch(msg)
		}

		switch m.screen {
		case screenAuthSetup:
			return m.updateAuthSetup(msg)
		case screenAuthLogin:
			return m.updateAuthLogin(msg)
		case screenDocs:
			return m.updateDocs(msg)
		case screenItems:
			return m.updateItems(msg)
		}
	}
	return m, nil
}

func (m Model) updateAuthSetup(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "tab":
		if m.activeField == fieldAuthSetupPass1 {
			m.activeField = fieldAuthSetupPass2
			m.auth1.Blur()
			m.auth2.Focus()
		} else {
			m.activeField = fieldAuthSetupPass1
			m.auth2.Blur()
			m.auth1.Focus()
		}
		return m, nil
	case "enter":
		pass1 := m.auth1.Value()
		pass2 := m.auth2.Value()
		if len(pass1) < 8 {
			m.setError("Password must be at least 8 characters")
			return m, nil
		}
		if pass1 != pass2 {
			m.setError("Passwords do not match")
			return m, nil
		}
		sess, vault, err := m.store.Initialize(pass1)
		if err != nil {
			m.setError(err.Error())
			return m, nil
		}
		m.sess = sess
		m.vault = vault
		m.screen = screenDocs
		m.activeField = fieldNone
		m.setStatus("Vault created successfully")
		m.rebuildDocFilter()
		return m, nil
	}

	var cmd tea.Cmd
	if m.activeField == fieldAuthSetupPass1 {
		m.auth1, cmd = m.auth1.Update(msg)
	} else {
		m.auth2, cmd = m.auth2.Update(msg)
	}
	return m, cmd
}

func (m Model) updateAuthLogin(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "enter":
		if m.auth3.Value() == "" {
			m.setError("Password is required")
			return m, nil
		}
		sess, vault, err := m.store.Unlock(m.auth3.Value())
		if err != nil {
			m.setError(err.Error())
			return m, nil
		}
		m.sess = sess
		m.vault = vault
		m.screen = screenDocs
		m.activeField = fieldNone
		m.setStatus("Logged in")
		m.rebuildDocFilter()
		return m, nil
	}
	var cmd tea.Cmd
	m.auth3, cmd = m.auth3.Update(msg)
	return m, cmd
}

func (m Model) updateDocs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.vault == nil {
		m.setError("vault is not loaded")
		return m, nil
	}
	if m.modal != modalNone {
		return m.updateModal(msg)
	}

	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "ctrl+l":
		return m.logout()
	case "ctrl+s":
		m.activeField = fieldSearch
		m.searchInput.SetValue(m.docsFilter)
		m.searchInput.Focus()
		return m, nil
	case "ctrl+a":
		return m.openDocForm(false)
	case "ctrl+e":
		return m.openDocForm(true)
	case "ctrl+d":
		if len(m.docsFiltered) == 0 {
			return m, nil
		}
		m.modal = modalConfirmDeleteDoc
		m.pendingDocIndex = m.docsFiltered[m.docsSelected]
		m.setStatus("Confirm delete document with Y/Enter")
		return m, nil
	case "enter":
		if len(m.docsFiltered) == 0 {
			return m, nil
		}
		m.screen = screenItems
		m.mode = modeItems
		m.itemsFilter = ""
		m.itemsSelected = 0
		m.rebuildItemFilter()
		m.setStatus("Opened document")
		return m, nil
	case "up", "k":
		if len(m.docsFiltered) > 0 && m.docsSelected > 0 {
			m.docsSelected--
			m.rebuildItemFilter()
		}
		return m, nil
	case "down", "j":
		if len(m.docsFiltered) > 0 && m.docsSelected < len(m.docsFiltered)-1 {
			m.docsSelected++
			m.rebuildItemFilter()
		}
		return m, nil
	}
	return m, nil
}

func (m Model) updateItems(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.vault == nil {
		m.setError("vault is not loaded")
		return m, nil
	}
	if m.modal != modalNone {
		return m.updateModal(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		if len(m.itemsFiltered) == 0 || len(m.docsFiltered) == 0 {
			return m, nil
		}
		doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
		item := doc.Items[m.itemsFiltered[m.itemsSelected]]
		if err := copyToClipboard(item.Secret); err != nil {
			m.setError(err.Error())
			return m, nil
		}
		m.setStatus("Secret copied to clipboard")
		return m, nil
	case "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "ctrl+l":
		return m.logout()
	case "esc":
		m.screen = screenDocs
		m.mode = modeDocs
		m.activeField = fieldNone
		m.itemsFilter = ""
		m.rebuildItemFilter()
		m.setStatus("Back to documents")
		return m, nil
	case "ctrl+s":
		m.activeField = fieldSearch
		m.searchInput.SetValue(m.itemsFilter)
		m.searchInput.Focus()
		return m, nil
	case "ctrl+a":
		return m.openItemForm(false)
	case "ctrl+e":
		return m.openItemForm(true)
	case "ctrl+d":
		if len(m.itemsFiltered) == 0 {
			return m, nil
		}
		m.modal = modalConfirmDeleteItem
		m.pendingItemIndex = m.itemsFiltered[m.itemsSelected]
		m.setStatus("Confirm delete item with Y/Enter")
		return m, nil
	case "up", "k":
		if len(m.itemsFiltered) > 0 && m.itemsSelected > 0 {
			m.itemsSelected--
		}
		return m, nil
	case "down", "j":
		if len(m.itemsFiltered) > 0 && m.itemsSelected < len(m.itemsFiltered)-1 {
			m.itemsSelected++
		}
		return m, nil
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		m.activeField = fieldNone
		m.searchInput.Blur()
		m.searchInput.SetValue("")
		if m.screen == screenDocs {
			m.docsFilter = ""
			m.rebuildDocFilter()
		} else {
			m.itemsFilter = ""
			m.rebuildItemFilter()
		}
		m.setStatus("Search cleared")
		return m, nil
	case "enter":
		m.activeField = fieldNone
		m.searchInput.Blur()
		m.setStatus("Search applied")
		return m, nil
	}

	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	if m.screen == screenDocs {
		m.docsFilter = strings.TrimSpace(m.searchInput.Value())
		m.rebuildDocFilter()
	} else {
		m.itemsFilter = strings.TrimSpace(m.searchInput.Value())
		m.rebuildItemFilter()
	}
	return m, cmd
}

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	}
	switch m.activeField {
	case fieldDocName:
		switch msg.String() {
		case "esc":
			m.activeField = fieldNone
			m.docInput.Blur()
			m.setStatus("Canceled")
			return m, nil
		case "enter":
			return m.saveDocFromForm()
		}
		var cmd tea.Cmd
		m.docInput, cmd = m.docInput.Update(msg)
		return m, cmd

	case fieldItemName, fieldItemSecret:
		switch msg.String() {
		case "esc":
			m.activeField = fieldNone
			m.itemName.Blur()
			m.itemSecret.Blur()
			m.setStatus("Canceled")
			return m, nil
		case "tab":
			if m.activeField == fieldItemName {
				m.activeField = fieldItemSecret
				m.itemName.Blur()
				m.itemSecret.Focus()
			} else {
				m.activeField = fieldItemName
				m.itemSecret.Blur()
				m.itemName.Focus()
			}
			return m, nil
		case "enter":
			if m.activeField == fieldItemName {
				m.activeField = fieldItemSecret
				m.itemName.Blur()
				m.itemSecret.Focus()
				return m, nil
			}
			return m.saveItemFromForm()
		}
		var cmd tea.Cmd
		if m.activeField == fieldItemName {
			m.itemName, cmd = m.itemName.Update(msg)
		} else {
			m.itemSecret, cmd = m.itemSecret.Update(msg)
		}
		return m, cmd
	}

	return m, nil
}

func (m Model) updateModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+q":
		m.quitting = true
		return m, tea.Quit
	case "esc", "n", "ctrl+c":
		m.modal = modalNone
		m.setStatus("Canceled")
		return m, nil
	case "y", "enter":
		switch m.modal {
		case modalConfirmDeleteDoc:
			return m.deleteDoc()
		case modalConfirmDeleteItem:
			return m.deleteItem()
		}
	}
	return m, nil
}

func (m *Model) saveDocFromForm() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.docInput.Value())
	if name == "" {
		m.setError("Document name cannot be empty")
		return *m, nil
	}
	now := time.Now()
	if m.formTitle == "Edit document" {
		if len(m.docsFiltered) == 0 {
			return *m, nil
		}
		doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
		doc.Name = name
		doc.UpdatedAt = now
		m.setStatus("Document updated")
	} else {
		m.vault.Documents = append(m.vault.Documents, model.Document{
			ID:        newID(),
			Name:      name,
			Items:     []model.Item{},
			CreatedAt: now,
			UpdatedAt: now,
		})
		m.docsSelected = len(m.vault.Documents) - 1
		m.setStatus("Document added")
	}
	if err := m.saveVault(); err != nil {
		m.setError(err.Error())
		return *m, nil
	}
	m.activeField = fieldNone
	m.docInput.Blur()
	m.rebuildDocFilter()
	return *m, nil
}

func (m *Model) saveItemFromForm() (tea.Model, tea.Cmd) {
	if len(m.docsFiltered) == 0 {
		return *m, nil
	}
	doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
	name := strings.TrimSpace(m.itemName.Value())
	secret := m.itemSecret.Value()
	if name == "" {
		m.setError("Item name cannot be empty")
		return *m, nil
	}
	now := time.Now()
	if m.formTitle == "Edit item" {
		if len(m.itemsFiltered) == 0 {
			return *m, nil
		}
		item := &doc.Items[m.itemsFiltered[m.itemsSelected]]
		item.Name = name
		item.Secret = secret
		item.UpdatedAt = now
		m.setStatus("Item updated")
	} else {
		doc.Items = append(doc.Items, model.Item{
			ID:        newID(),
			Name:      name,
			Secret:    secret,
			CreatedAt: now,
			UpdatedAt: now,
		})
		m.itemsSelected = len(doc.Items) - 1
		m.setStatus("Item added")
	}
	doc.UpdatedAt = now
	if err := m.saveVault(); err != nil {
		m.setError(err.Error())
		return *m, nil
	}
	m.activeField = fieldNone
	m.itemName.Blur()
	m.itemSecret.Blur()
	m.rebuildItemFilter()
	return *m, nil
}

func (m *Model) deleteDoc() (tea.Model, tea.Cmd) {
	if len(m.docsFiltered) == 0 || m.pendingDocIndex < 0 || m.pendingDocIndex >= len(m.vault.Documents) {
		m.modal = modalNone
		return *m, nil
	}
	deletedName := m.vault.Documents[m.pendingDocIndex].Name
	m.vault.Documents = append(m.vault.Documents[:m.pendingDocIndex], m.vault.Documents[m.pendingDocIndex+1:]...)
	if m.docsSelected >= len(m.docsFiltered) && m.docsSelected > 0 {
		m.docsSelected--
	}
	if err := m.saveVault(); err != nil {
		m.setError(err.Error())
		return *m, nil
	}
	m.modal = modalNone
	m.rebuildDocFilter()
	m.setStatus("Deleted document: " + deletedName)
	return m, nil
}

func (m *Model) deleteItem() (tea.Model, tea.Cmd) {
	if len(m.docsFiltered) == 0 || m.pendingItemIndex < 0 {
		m.modal = modalNone
		return *m, nil
	}
	doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
	if m.pendingItemIndex >= len(doc.Items) {
		m.modal = modalNone
		return *m, nil
	}
	deletedName := doc.Items[m.pendingItemIndex].Name
	doc.Items = append(doc.Items[:m.pendingItemIndex], doc.Items[m.pendingItemIndex+1:]...)
	doc.UpdatedAt = time.Now()
	if err := m.saveVault(); err != nil {
		m.setError(err.Error())
		return *m, nil
	}
	m.modal = modalNone
	m.rebuildItemFilter()
	m.setStatus("Deleted item: " + deletedName)
	return m, nil
}

func (m *Model) openDocForm(edit bool) (tea.Model, tea.Cmd) {
	m.screen = screenDocs
	m.activeField = fieldDocName
	m.docInput.Focus()
	if edit {
		if len(m.docsFiltered) == 0 {
			return *m, nil
		}
		doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
		m.docInput.SetValue(doc.Name)
		m.formTitle = "Edit document"
	} else {
		m.docInput.SetValue("")
		m.formTitle = "Add document"
	}
	return *m, nil
}

func (m *Model) openItemForm(edit bool) (tea.Model, tea.Cmd) {
	if len(m.docsFiltered) == 0 {
		return *m, nil
	}
	doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
	m.screen = screenItems
	m.activeField = fieldItemName
	m.itemName.Focus()
	m.itemSecret.Blur()
	if edit {
		if len(m.itemsFiltered) == 0 {
			return *m, nil
		}
		item := &doc.Items[m.itemsFiltered[m.itemsSelected]]
		m.itemName.SetValue(item.Name)
		m.itemSecret.SetValue(item.Secret)
		m.formTitle = "Edit item"
	} else {
		m.itemName.SetValue("")
		m.itemSecret.SetValue("")
		m.formTitle = "Add item"
	}
	return *m, nil
}

func (m *Model) logout() (tea.Model, tea.Cmd) {
	m.sess = nil
	m.vault = nil
	m.docsFilter = ""
	m.itemsFilter = ""
	m.docsFiltered = nil
	m.itemsFiltered = nil
	m.docsSelected = 0
	m.itemsSelected = 0
	m.activeField = fieldNone
	m.modal = modalNone
	m.auth1.SetValue("")
	m.auth2.SetValue("")
	m.auth3.SetValue("")
	m.docInput.SetValue("")
	m.itemName.SetValue("")
	m.itemSecret.SetValue("")
	if m.store.Exists() {
		m.screen = screenAuthLogin
		m.activeField = fieldAuthLoginPass
		m.auth3.Focus()
		m.auth1.Blur()
		m.auth2.Blur()
		m.setStatus("Logged out")
	} else {
		m.screen = screenAuthSetup
		m.activeField = fieldAuthSetupPass1
		m.auth1.Focus()
		m.auth2.Blur()
		m.auth3.Blur()
		m.setStatus("No vault found. Create one.")
	}
	return m, nil
}

func (m *Model) saveVault() error {
	if m.vault == nil || m.sess == nil {
		return fmt.Errorf("no active session")
	}
	return m.store.Save(m.vault, m.sess)
}

func (m *Model) rebuildDocFilter() {
	m.docsFiltered = m.docsFiltered[:0]
	if m.vault == nil {
		return
	}
	query := strings.ToLower(strings.TrimSpace(m.docsFilter))
	for i, d := range m.vault.Documents {
		if query == "" || strings.Contains(strings.ToLower(d.Name), query) {
			m.docsFiltered = append(m.docsFiltered, i)
		}
	}
	if len(m.docsFiltered) == 0 {
		m.docsSelected = 0
	} else if m.docsSelected >= len(m.docsFiltered) {
		m.docsSelected = len(m.docsFiltered) - 1
	}
	m.rebuildItemFilter()
}

func (m *Model) rebuildItemFilter() {
	m.itemsFiltered = m.itemsFiltered[:0]
	if m.vault == nil || len(m.docsFiltered) == 0 {
		return
	}
	doc := &m.vault.Documents[m.docsFiltered[m.docsSelected]]
	query := strings.ToLower(strings.TrimSpace(m.itemsFilter))
	for i, item := range doc.Items {
		hay := strings.ToLower(item.Name + " " + item.Secret)
		if query == "" || strings.Contains(hay, query) {
			m.itemsFiltered = append(m.itemsFiltered, i)
		}
	}
	if len(m.itemsFiltered) == 0 {
		m.itemsSelected = 0
	} else if m.itemsSelected >= len(m.itemsFiltered) {
		m.itemsSelected = len(m.itemsFiltered) - 1
	}
}

func (m *Model) setStatus(s string) {
	m.statusMsg = s
	m.errMsg = ""
}

func (m *Model) setError(s string) {
	m.errMsg = s
	m.statusMsg = ""
}

func (m Model) View() string {
	switch m.screen {
	case screenAuthSetup:
		return centerBox(panelStyle.Render(m.authSetupView()), m.width, m.height)
	case screenAuthLogin:
		return centerBox(panelStyle.Render(m.authLoginView()), m.width, m.height)
	case screenDocs:
		return m.docsScreenView()
	case screenItems:
		return m.itemsScreenView()
	default:
		return "..."
	}
}

func (m Model) authSetupView() string {
	parts := []string{
		titleStyle.Render(" Secret Manager || By AJ "),
		"",
		mutedStyle.Render("Create your master password for first use."),
		"",
		"Password",
		m.auth1.View(),
		"",
		"Confirm",
		m.auth2.View(),
		"",
		m.renderStatus(),
		"",
		mutedStyle.Render("Enter to continue · Tab to switch fields · Ctrl+Q to quit"),
	}
	return strings.Join(parts, "\n")
}

func (m Model) authLoginView() string {
	parts := []string{
		titleStyle.Render(" Secret Manager || By AJ "),
		"",
		mutedStyle.Render("Enter your master password."),
		"",
		"Password",
		m.auth3.View(),
		"",
		m.renderStatus(),
		"",
		mutedStyle.Render("Enter to unlock · Ctrl+Q to quit"),
	}
	return strings.Join(parts, "\n")
}

func (m Model) docsScreenView() string {
	left := m.docsListPanel()
	right := m.docsDetailPanel()
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	footer := m.renderFooter("Ctrl+S Search   Ctrl+A Add   Ctrl+E Edit   Ctrl+D Delete   Enter Open   Ctrl+L Logout   Ctrl+Q Quit")
	status := m.renderStatus()
	out := lipgloss.JoinVertical(lipgloss.Left, m.header("Documents"), "", body, "", status, "", footer)
	if m.activeField == fieldDocName {
		return m.overlay(out, m.docFormView())
	}
	if m.modal != modalNone {
		return m.overlay(out, m.confirmModalView())
	}
	return out
}

func (m Model) itemsScreenView() string {
	left := m.itemsListPanel()
	right := m.itemsDetailPanel()
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	footer := m.renderFooter("Ctrl+S Search   Ctrl+A Add   Ctrl+E Edit   Ctrl+D Delete   Ctrl+C Copy   Esc Back   Ctrl+L Logout   Ctrl+Q Quit")
	status := m.renderStatus()
	out := lipgloss.JoinVertical(lipgloss.Left, m.header("Items"), "", body, "", status, "", footer)
	if m.activeField == fieldItemName || m.activeField == fieldItemSecret {
		return m.overlay(out, m.itemFormView())
	}
	if m.modal != modalNone {
		return m.overlay(out, m.confirmModalView())
	}
	return out
}

func (m Model) header(title string) string {
	right := "locked"
	if m.vault != nil {
		right = fmt.Sprintf("%d documents", len(m.vault.Documents))
	}
	bar := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Padding(0, 1).Render(" " + title + " ")
	info := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(right)
	return lipgloss.JoinHorizontal(lipgloss.Top, bar, lipgloss.NewStyle().Width(max(0, m.width-lipgloss.Width(bar)-lipgloss.Width(info)-2)).Render(""), info)
}

func (m Model) renderFooter(text string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(text)
}

func (m Model) docsListPanel() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("Documents"))
	b.WriteString("\n")
	if m.activeField == fieldSearch && m.screen == screenDocs {
		b.WriteString("Search: ")
		b.WriteString(m.searchInput.View())
		b.WriteString("\n\n")
	} else {
		b.WriteString(mutedStyle.Render("Ctrl+S to search"))
		b.WriteString("\n\n")
	}
	if len(m.docsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("No documents found"))
		return panelStyle.Width(max(40, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	for i, idx := range m.docsFiltered {
		doc := m.vault.Documents[idx]
		line := fmt.Sprintf("%s  %s", bullet(i == m.docsSelected), doc.Name)
		if i == m.docsSelected {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return panelStyle.Width(max(40, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
}

func (m Model) docsDetailPanel() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("Preview"))
	b.WriteString("\n\n")
	if len(m.docsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("Create or search for a document."))
		return panelStyle.Width(max(45, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	doc := m.vault.Documents[m.docsFiltered[m.docsSelected]]
	b.WriteString("Name: " + doc.Name + "\n")
	b.WriteString(fmt.Sprintf("Items: %d\n", len(doc.Items)))
	b.WriteString("Updated: " + doc.UpdatedAt.Format("2006-01-02 15:04:05") + "\n\n")
	b.WriteString(mutedStyle.Render("Enter open · Ctrl+A add · Ctrl+E edit · Ctrl+D delete · Ctrl+L logout"))
	return panelStyle.Width(max(45, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
}

func (m Model) itemsListPanel() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("Items"))
	b.WriteString("\n")
	if m.activeField == fieldSearch && m.screen == screenItems {
		b.WriteString("Search: ")
		b.WriteString(m.searchInput.View())
		b.WriteString("\n\n")
	} else {
		b.WriteString(mutedStyle.Render("Ctrl+S to search"))
		b.WriteString("\n\n")
	}
	if len(m.docsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("No document selected"))
		return panelStyle.Width(max(40, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	if len(m.itemsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("No items found"))
		return panelStyle.Width(max(40, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	doc := m.vault.Documents[m.docsFiltered[m.docsSelected]]
	for i, idx := range m.itemsFiltered {
		item := doc.Items[idx]
		line := fmt.Sprintf("%s  %s", bullet(i == m.itemsSelected), item.Name)
		if i == m.itemsSelected {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	return panelStyle.Width(max(40, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
}

func (m Model) itemsDetailPanel() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("Secret preview"))
	b.WriteString("\n\n")
	if len(m.docsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("Open a document first."))
		return panelStyle.Width(max(45, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	doc := m.vault.Documents[m.docsFiltered[m.docsSelected]]
	if len(m.itemsFiltered) == 0 {
		b.WriteString(mutedStyle.Render("Create or search for an item."))
		return panelStyle.Width(max(45, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
	}
	item := doc.Items[m.itemsFiltered[m.itemsSelected]]
	b.WriteString("Name: " + item.Name + "\n")
	b.WriteString("Secret: " + maskSecret(item.Secret) + "\n")
	b.WriteString("Updated: " + item.UpdatedAt.Format("2006-01-02 15:04:05") + "\n\n")
	b.WriteString(mutedStyle.Render("Ctrl+C copy · Ctrl+A add · Ctrl+E edit · Ctrl+D delete · Esc back"))
	return panelStyle.Width(max(45, m.width/2-6)).Height(max(18, m.height-10)).Render(b.String())
}

func (m Model) docFormView() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render(" "+m.formTitle+" "),
		"",
		"Document name",
		m.docInput.View(),
		"",
		mutedStyle.Render("Enter to save · Esc to cancel"),
	)
	return centerBox(panelStyle.Render(content), m.width, m.height)
}

func (m Model) itemFormView() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render(" "+m.formTitle+" "),
		"",
		"Item name",
		m.itemName.View(),
		"",
		"Secret value",
		m.itemSecret.View(),
		"",
		mutedStyle.Render("Enter to save · Tab to switch fields · Esc to cancel"),
	)
	return centerBox(panelStyle.Render(content), m.width, m.height)
}

func (m Model) confirmModalView() string {
	text := "Confirm action? Press Y or Enter to continue, N or Esc to cancel."
	if m.modal == modalConfirmDeleteDoc {
		text = "Delete this document? Press Y or Enter to continue, N or Esc to cancel."
	} else if m.modal == modalConfirmDeleteItem {
		text = "Delete this item? Press Y or Enter to continue, N or Esc to cancel."
	}
	content := lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render(" Confirm "),
		"",
		text,
	)
	return centerBox(panelStyle.Render(content), m.width, m.height)
}

func (m Model) overlay(base, top string) string {
	return base + "\n\n" + top
}

func (m Model) renderStatus() string {
	if m.errMsg != "" {
		return dangerStyle.Render(m.errMsg)
	}
	if m.statusMsg != "" {
		return okStyle.Render(m.statusMsg)
	}
	return ""
}

func centerBox(content string, width, height int) string {
	return lipgloss.Place(max(0, width), max(0, height), lipgloss.Center, lipgloss.Center, content)
}

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("57")).Padding(0, 1)
	panelStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")).Padding(1, 2)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("229")).Background(lipgloss.Color("62")).Bold(true)
	mutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	dangerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	accentStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
)

func bullet(selected bool) string {
	if selected {
		return "▶"
	}
	return "•"
}

func maskSecret(s string) string {
	if s == "" {
		return "(empty)"
	}
	n := 12
	if len([]rune(s)) < n {
		n = len([]rune(s))
	}
	return strings.Repeat("•", n)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func copyToClipboard(text string) error {
	if text == "" {
		return fmt.Errorf("nothing to copy")
	}
	var commands [][]string
	switch runtime.GOOS {
	case "darwin":
		commands = [][]string{{"pbcopy"}}
	case "windows":
		commands = [][]string{{"cmd", "/c", "clip"}}
	default:
		commands = [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		}
	}
	for _, args := range commands {
		if _, err := exec.LookPath(args[0]); err != nil {
			continue
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("clipboard utility not found; install wl-copy, xclip, xsel, or pbcopy support")
}

func newID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}
