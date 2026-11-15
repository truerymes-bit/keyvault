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
// for manual review, never silently dropped. Provider is the section heading
// the line appeared under ("" when there was none); it is data, not a guess.
type UnmatchedLine struct {
	Line     int    `json:"line"`
	Text     string `json:"text"`
	Reason   string `json:"reason"`
	Provider string `json:"provider,omitempty"`
}

// NewProvider is a heading that looked like a provider but is not in the
// built-in or custom provider list. Records parsed under it are grouped here
// for the user to confirm with one click, instead of being reported as
// unmatched lines. Suggestion is the closest known provider name when the
// heading is within two edits of one; the UI offers it as a one-click accept
// and never corrects the heading silently.
type NewProvider struct {
	Name       string   `json:"name"`
	Suggestion string   `json:"suggestion,omitempty"`
	Records    []Record `json:"records,omitempty"`
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

// keyOnlyRe matches a key-only line: a single token of at least 16
// characters drawn from letters, digits, dots, underscores and hyphens,
// with no slash.
var keyOnlyRe = regexp.MustCompile(`^[A-Za-z0-9._-]{16,}$`)

// isKeyOnly reports whether a no-email, single-token line is key-looking and
// should be returned as a record with an empty email (provider still set)
// rather than classified as a provider heading.
func isKeyOnly(line string) bool {
	if strings.ContainsAny(line, " 	@/") {
		return false
	}
	return keyOnlyRe.MatchString(line)
}

// lineKind is the classification of one non-blank input line. A heading
// candidate is only promoted to a real heading when a record follows it
// before the next heading or unrecognized line.
type lineKind int

const (
	kindBlank lineKind = iota
	kindRecord
	kindKeyOnly
	kindMalformed
	kindUnrecognized
	kindHeading
)

func classifyLine(line string) lineKind {
	if line == "" {
		return kindBlank
	}
	if emailStartRe.MatchString(line) {
		return kindRecord
	}
	if strings.Contains(line, "@") {
		return kindMalformed
	}
	if isUnrecognizedLine(line) {
		return kindUnrecognized
	}
	if isKeyOnly(line) {
		return kindKeyOnly
	}
	if headingWordRe.MatchString(stripTrailingPhrase(trimTrailingPunct(line))) {
		return kindHeading
	}
	return kindUnrecognized
}

// headingConfirmed reports whether a record follows the heading candidate at
// index i before the next heading or unrecognized line. Blank lines and
// malformed record lines are skipped; a malformed line is a broken record,
// not a heading or an unrecognized line.
func headingConfirmed(kinds []lineKind, i int) bool {
	for j := i + 1; j < len(kinds); j++ {
		switch kinds[j] {
		case kindBlank, kindMalformed:
			continue
		case kindRecord, kindKeyOnly:
			return true
		default:
			return false
		}
	}
	return false
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
	kinds := make([]lineKind, len(lines))
	for i, raw := range lines {
		kinds[i] = classifyLine(strings.TrimSpace(raw))
	}

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		switch kinds[i] {
		case kindRecord:
			m := emailStartRe.FindStringSubmatch(line)
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

		case kindKeyOnly:
			// Key-only line under a heading: record with an empty email that
			// the user must fill in before the key is useful.
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

		case kindMalformed:
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:     lineNo,
				Text:     line,
				Reason:   "malformed record",
				Provider: current,
			})

		case kindUnrecognized:
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:     lineNo,
				Text:     line,
				Reason:   "unrecognized line",
				Provider: current,
			})

		case kindHeading:
			// A no-email line is a provider heading only if at least one
			// record follows it before the next heading or unrecognized
			// line. Otherwise it is an unrecognized line, never a provider.
			if !headingConfirmed(kinds, i) {
				res.Unmatched = append(res.Unmatched, UnmatchedLine{
					Line:     lineNo,
					Text:     line,
					Reason:   "unrecognized line",
					Provider: current,
				})
				continue
			}
			candidate := stripTrailingPhrase(trimTrailingPunct(line))
			if name, ok := matchKnownCaseInsensitive(candidate, known); ok {
				current = name
				continue
			}

			// Unknown candidate heading: group records under it as a new
			// provider candidate. If it is within two edits of a known
			// provider, offer that name as a one-click suggestion; never
			// correct the heading silently.
			name := candidate
			np := &NewProvider{Name: name}
			if s := suggestProvider(name, known, 2); s != "" {
				np.Suggestion = s
			}
			res.NewProviders = append(res.NewProviders, np)
			newProviders[name] = np
			current = name
		}
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

// levenshtein returns the edit distance between a and b, comparing
// case-insensitively. It is the classic dynamic-programming distance with
// unit costs for insert, delete and substitute.
func levenshtein(a, b string) int {
	ar := []rune(strings.ToLower(a))
	br := []rune(strings.ToLower(b))
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			m := prev[j] + 1
			if cur[j-1]+1 < m {
				m = cur[j-1] + 1
			}
			if prev[j-1]+cost < m {
				m = prev[j-1] + cost
			}
			cur[j] = m
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// suggestProvider returns the closest known provider name to name within
// maxEdits edits, or "" when no known name is close enough. It never
// returns the name itself; callers only invoke it for unknown headings.
func suggestProvider(name string, known []string, maxEdits int) string {
	best := ""
	bestDist := maxEdits + 1
	for _, k := range known {
		d := levenshtein(name, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	if bestDist <= maxEdits {
		return best
	}
	return ""
}
