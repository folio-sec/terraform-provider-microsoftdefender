// Package docs builds Markdown for Terraform Registry provider documentation.
package docs

import (
	"fmt"
	"strings"
)

// Callout sigils recognized by the Terraform Registry.
const (
	Danger  = "!>"
	Warning = "~>"
	Info    = "->"
)

// Callout is a single Terraform Registry callout paragraph.
type Callout struct {
	Sigil string
	Label string
	Text  string
}

func (c Callout) String() string {
	return fmt.Sprintf("%s **%s:** %s", c.Sigil, c.Label, strings.Join(strings.Fields(c.Text), " "))
}

// Description joins a summary sentence with Terraform Registry callouts.
func Description(summary string, callouts ...Callout) string {
	paragraphs := make([]string, 0, len(callouts)+1)
	paragraphs = append(paragraphs, strings.Join(strings.Fields(summary), " "))
	for _, callout := range callouts {
		paragraphs = append(paragraphs, callout.String())
	}
	return strings.Join(paragraphs, "\n\n")
}
