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

// NewProvider is a heading that looked like a provider but is not in the
// built-in or custom provider list. Records parsed under it are grouped here
// for the user to confirm with one click, instead of being reported as
// unmatched lines.
type NewProvider struct {
	Name    string   `json:"name"`
	Records []Record `json:"records,omitempty"`
}

// Result is the output of parsing a document.
type Result struct {
	Records      []Record        `json:"records"`
	Unmatched    []UnmatchedLine `json:"unmatched"`
	NewProviders []*NewProvider  `json:"new_providers,omitempty"`
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

// trimTrailingPunct removes trailing heading punctuation from a candidate
// provider name ("AnotherNewOne:" -> "AnotherNewOne"). Internal punctuation
// is preserved so names like "My-Provider" keep their hyphen.
func trimTrailingPunct(s string) string {
	return strings.TrimRight(s, ":;,.!-–—*_ ")
}

// candidateProviderName returns the heading portion of a candidate line.
// When a key is glued to a heading on the same line ("ElevenLabs:sk-…"),
// the key (a token with no spaces after the colon) is not part of the
// heading name.
func candidateProviderName(line string) string {
	if i := strings.Index(line, ":"); i >= 0 {
		rest := line[i+1:]
		if rest != "" && !strings.ContainsAny(rest, " 	") {
			return trimTrailingPunct(line[:i])
		}
	}
	return trimTrailingPunct(line)
}

// ParseTXT parses a plain-text import document. customProviders are extra
// recognized provider names (e.g. added by the user); they are matched the
// same way as the defaults.
func ParseTXT(input string, customProviders ...string) *Result {
	known := append(append([]string{}, DefaultProviders...), customProviders...)
	res := &Result{}
	current := ""
	newProviders := make(map[string]*NewProvider)

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
			if np, ok := newProviders[current]; ok {
				np.Records = append(np.Records, rec)
			}
			continue
		}

		// Provider heading? Longest names first so "Google Gemini" wins
		// over "Gemini" when both could match.
		norm := strings.ToLower(strings.TrimSpace(headingTrailingPunct.Replace(line)))
		if name, ok := matchHeading(norm, known); ok {
			current = name
			continue
		}

		// Not a recognized heading and not a broken record (contains '@').
		// A line with no email that looks like a heading is a candidate
		// provider: group records under it and return it as a "new provider
		// detected" item for user confirmation, not as an unmatched line.
		if strings.Contains(line, "@") {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{Line: lineNo, Text: line, Reason: "malformed record"})
			continue
		}
		name := candidateProviderName(line)
		np := &NewProvider{Name: name}
		res.NewProviders = append(res.NewProviders, np)
		newProviders[name] = np
		current = name
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
