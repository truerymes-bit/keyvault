// Package importer parses bulk-import files (TXT and CSV) into candidate
// records. Parsing never writes to the database; the import session flow
// handles validation, preview, duplicates and commit.
package importer

import (
	"regexp"
	"strings"
	"unicode"
)

// Record is one parsed email/key candidate.
type Record struct {
	Line     int    `json:"line"`
	Email    string `json:"email"`
	Key      string `json:"key"`
	Provider string `json:"provider"`
	Status   string `json:"status"` // "ok", "no_provider", or "needs_attention"
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
const StatusNeedsAttention = "needs_attention"

// trimTrailingPunct removes trailing heading punctuation from a candidate
// provider name ("AnotherNewOne:" -> "AnotherNewOne"). Internal punctuation
// is preserved so names like "My-Provider" keep their hyphen.
func trimTrailingPunct(s string) string {
	return strings.TrimRight(s, ":;,.!-–—*_ ")
}

// stripTrailingPhrase removes a trailing key phrase so the classifier sees
// the bare provider name ("Gemini API Key" -> "Gemini", "ElevenLabs Keys"
// -> "ElevenLabs"). The phrase must be a separate word at the end of the
// string, not embedded in a larger word.
func stripTrailingPhrase(s string) string {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	for _, phrase := range []string{"api keys", "api key", "keys"} {
		if idx := strings.LastIndex(lower, phrase); idx >= 0 && idx+len(phrase) == len(lower) {
			if idx == 0 {
				return ""
			}
			if unicode.IsSpace(rune(lower[idx-1])) {
				return strings.TrimSpace(s[:idx])
			}
		}
	}
	return s
}

// headingWordRe matches a provider heading candidate: 1 to 3 words made of
// letters, digits, dots and hyphens. Hyphens and dots are allowed inside a
// word so names like "My-Provider" and "v1.2" classify as single words.
var headingWordRe = regexp.MustCompile(`^[A-Za-z0-9.-]+(?: [A-Za-z0-9.-]+){0,2}$`)

// isUnrecognizedLine reports whether a non-record line is a sentence,
// "Name: value" pair, or other line that is never a provider heading.
func isUnrecognizedLine(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "http") || strings.Contains(lower, "/") || strings.Contains(lower, "$") {
		return true
	}
	if strings.ContainsAny(line, "()" /* parentheses */) {
		return true
	}
	// "Name: value" pair: a colon followed by a non-space character.
	if idx := strings.IndexByte(line, ':'); idx >= 0 {
		if idx+1 < len(line) && !unicode.IsSpace(rune(line[idx+1])) {
			return true
		}
	}
	return false
}

// keyOnlyRe matches a single-token key-like line: whitespace-free, no "@",
// long enough, and carrying characters a provider name would not use.
var keyOnlyRe = regexp.MustCompile(`^[A-Za-z0-9_\-.]{12,}$`)

// isKeyOnly reports whether a no-email, single-token line is key-looking and
// should be returned as a record with an empty email (provider still set)
// rather than classified as a provider heading.
func isKeyOnly(line string) bool {
	if strings.ContainsAny(line, " \t@") || !keyOnlyRe.MatchString(line) {
		return false
	}
	// A plain alphabetic word (possibly hyphenated) is treated as a heading
	// name below, not a key.
	if containsOnlyLetters(line) {
		return false
	}
	if strings.ContainsAny(line, "0123456789") {
		return true
	}
	if strings.Contains(line, "_") || strings.Contains(line, "..") {
		return true
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "sk_") ||
		strings.HasPrefix(lower, "aiza") || strings.HasPrefix(lower, "opn-") ||
		strings.HasPrefix(lower, "ghp_") || strings.HasPrefix(lower, "gho_") ||
		strings.HasPrefix(lower, "xoxb_") || strings.HasPrefix(lower, "pk_") ||
		strings.HasPrefix(lower, "rk_") {
		return true
	}
	return false
}

func containsOnlyLetters(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
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

		// A line containing "@" that is not an email record is malformed.
		if strings.Contains(line, "@") {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:   lineNo,
				Text:   line,
				Reason: "malformed record",
			})
			continue
		}

		// Sentences, "Name: value" pairs, slashes, http, "$", parentheses.
		if isUnrecognizedLine(line) {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:   lineNo,
				Text:   line,
				Reason: "unrecognized line",
			})
			continue
		}

		// Key-only line under a heading: record with an empty email that the
		// user must fill in before the key is useful.
		if isKeyOnly(line) {
			res.Records = append(res.Records, Record{
				Line:     lineNo,
				Email:    "",
				Key:      line,
				Provider: current,
				Status:   StatusNeedsAttention,
			})
			if np, ok := newProviders[current]; ok {
				np.Records = append(np.Records, res.Records[len(res.Records)-1])
			}
			continue
		}

		// Provider heading: strip trailing punctuation and trailing key
		// phrases, then require 1 to 3 words of letters, digits, dots, and
		// hyphens. Known names match case-insensitively.
		candidate := trimTrailingPunct(line)
		candidate = stripTrailingPhrase(candidate)
		if !headingWordRe.MatchString(candidate) {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:   lineNo,
				Text:   line,
				Reason: "unrecognized line",
			})
			continue
		}
		if name, ok := matchKnownCaseInsensitive(candidate, known); ok {
			current = name
			continue
		}

		// Unknown candidate heading: group records under it as a new
		// provider candidate.
		name := candidate
		np := &NewProvider{Name: name}
		res.NewProviders = append(res.NewProviders, np)
		newProviders[name] = np
		current = name
	}
	return res
}

// matchKnownCaseInsensitive reports whether norm is one of the known
// provider names, ignoring case, and returns the canonical name.
func matchKnownCaseInsensitive(norm string, known []string) (string, bool) {
	norm = strings.ToLower(norm)
	for _, name := range known {
		if strings.ToLower(name) == norm {
			return name, true
		}
	}
	return "", false
}
