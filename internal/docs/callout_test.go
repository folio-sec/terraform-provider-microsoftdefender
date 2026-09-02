package docs

import (
	"strings"
	"testing"
)

func TestDescription(t *testing.T) {
	t.Parallel()

	description := Description(
		"RBAC device group names.",
		Callout{Sigil: Warning, Label: "Warning", Text: "An empty or omitted set\n\tapplies to all devices."},
		Callout{Sigil: Info, Label: "Tip", Text: "Use a named group to limit scope."},
	)

	want := []string{
		"RBAC device group names.",
		"~> **Warning:** An empty or omitted set applies to all devices.",
		"-> **Tip:** Use a named group to limit scope.",
	}
	paragraphs := strings.Split(description, "\n\n")
	if len(paragraphs) != len(want) {
		t.Fatalf("paragraphs = %#v, want %d paragraphs", paragraphs, len(want))
	}
	for index := range want {
		if paragraphs[index] != want[index] {
			t.Errorf("paragraph %d = %q, want %q", index, paragraphs[index], want[index])
		}
		if strings.Contains(paragraphs[index], "\n") {
			t.Errorf("paragraph %d contains a newline: %q", index, paragraphs[index])
		}
	}
}

func TestDescriptionWithoutCallouts(t *testing.T) {
	t.Parallel()

	if got := Description("Indicator description."); got != "Indicator description." {
		t.Errorf("Description() = %q", got)
	}
}
