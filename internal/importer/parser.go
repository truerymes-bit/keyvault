// Package importer parses bulk-import files (TXT and CSV) into candidate
// records. Parsing never writes to the database; the import session flow
// handles validation, preview, duplicates and commit.
package importer

import (
	"regexp"
	"strings"
)

// Record is one parsed email/key candidate.
type Record struct {
	Line     int    `json:"line"`
	Email    string `json:"email"`
	Key      string `json:"key"`
	Provider string `json:"provider"`
	Status   string `json:"status"` // "ok" or "no_provider"
}

// UnmatchedLine is a line the parser could not classify. It is preserved
// for manual review, never silently dropped.
type UnmatchedLine struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

// Result is the output of parsing a document.
type Result struct {
	Records   []Record        `json:"records"`
	Unmatched []UnmatchedLine `json:"unmatched"`
}

// DefaultProviders are the provider names recognized out of the box.
var DefaultProviders = []string{
	"Gemini", "Google AI", "Google Gemini",
	"OpenRouter", "ElevenLabs",
	"OpenAI", "Anthropic", "Claude",
}

var emailStartRe = regexp.MustCompile(`^([^\s@]+@[^\s@]+\.[^\s@]+)\s+(\S.*)$`)

const StatusOK = "ok"
const StatusNoProvider = "no_provider"

var headingTrailingPunct = strings.NewReplacer(
	":", "", ";", "", ",", "", ".", "", "!", "", "-", "", "–", "", "—", "", "*", "", "_", "",
)

// ParseTXT parses a plain-text import document. customProviders are extra
// recognized provider names (e.g. added by the user); they are matched the
// same way as the defaults.
func ParseTXT(input string, customProviders ...string) *Result {
	known := append(append([]string{}, DefaultProviders...), customProviders...)
	res := &Result{}
	current := ""

	lines := strings.Split(input, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// Email/key record?
		if m := emailStartRe.FindStringSubmatch(line); m != nil {
			rec := Record{
				Line:     lineNo,
				Email:    m[1],
				Key:      strings.TrimSpace(m[2]),
				Provider: current,
				Status:   StatusOK,
			}
			if current == "" {
				rec.Status = StatusNoProvider
			}
			res.Records = append(res.Records, rec)
			continue
		}

		// Provider heading? Longest names first so "Google Gemini" wins
		// over "Gemini" when both could match.
		norm := strings.ToLower(strings.TrimSpace(headingTrailingPunct.Replace(line)))
		if name, ok := matchHeading(norm, known); ok {
			current = name
			continue
		}

		// Unrecognized. Lines containing '@' look like broken records and
		// keep the current context; anything else looks like an unknown
		// heading, so provider context is cleared fail-safe.
		if strings.Contains(line, "@") {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{Line: lineNo, Text: line, Reason: "malformed record"})
		} else {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{Line: lineNo, Text: line, Reason: "unrecognized heading"})
			current = ""
		}
	}
	return res
}

// matchHeading reports whether norm (lowercased, punctuation-stripped,
// space-trimmed) is a known provider name optionally followed by trailing
// words. Returns the canonical provider name.
func matchHeading(norm string, known []string) (string, bool) {
	sorted := append([]string{}, known...)
	// Longest first so multi-word names match before their prefixes.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && len(strings.ToLower(sorted[j])) > len(strings.ToLower(sorted[j-1])); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	for _, name := range sorted {
		lname := strings.ToLower(name)
		if norm == lname {
			return name, true
		}
		if strings.HasPrefix(norm, lname+" ") {
			// Trailing words allowed on a heading line ("Gemini API Key",
			// "ElevenLabs Keys"). Reject if the remainder holds an '@'.
			rest := norm[len(lname)+1:]
			if !strings.Contains(rest, "@") {
				return name, true
			}
		}
	}
	return "", false
}
