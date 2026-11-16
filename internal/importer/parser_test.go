package importer

import "testing"

const specExample = `Gemini API Key

user1@example.com AQ.Ab8RN6KwaaGNVNXaa
user2@example.com AQ.Ab8RN6KwaaGNVNXbb
user3@example.com AQ.Ab8RN6KwaaGNVNXcc

OpenRouter

user1@example.com or-key-123*&^%
user2@example.com or-key-456!@#$

ElevenLabs

user1@example.com sk_227b6f7c00abcdef1234567890
`

func TestSpecExampleParses(t *testing.T) {
	res := ParseTXT(specExample)
	if len(res.Unmatched) != 0 {
		t.Fatalf("unexpected unmatched lines: %+v", res.Unmatched)
	}
	want := []struct {
		email, provider string
	}{
		{"user1@example.com", "Gemini"},
		{"user2@example.com", "Gemini"},
		{"user3@example.com", "Gemini"},
		{"user1@example.com", "OpenRouter"},
		{"user2@example.com", "OpenRouter"},
		{"user1@example.com", "ElevenLabs"},
	}
	if len(res.Records) != len(want) {
		t.Fatalf("records = %d, want %d: %+v", len(res.Records), len(want), res.Records)
	}
	for i, w := range want {
		r := res.Records[i]
		if r.Email != w.email || r.Provider != w.provider {
			t.Errorf("record %d = (%q, %q), want (%q, %q)", i, r.Email, r.Provider, w.email, w.provider)
		}
		if r.Status != StatusOK {
			t.Errorf("record %d status = %q, want ok", i, r.Status)
		}
	}
}

func TestAmendment10Headings(t *testing.T) {
	// Fixture, line by line:
	//   1 "Gemini API Key"   -> trailing words stripped -> Gemini
	//   2 "a@b.com k1"       -> record under Gemini
	//   3 "OpenRouter:"      -> trailing colon stripped -> OpenRouter
	//   4 "b@c.com k2"       -> record under OpenRouter
	//   5 "ElevenLabs Keys"  -> trailing words stripped -> ElevenLabs
	//   6 "d@e.com k3"       -> record under ElevenLabs
	//   7 "Google Gemini"    -> known heading
	//   8 "f@g.com k4"       -> record under Google Gemini
	// Arithmetic: 4 records, 0 unmatched, 0 new providers.
	input := "Gemini API Key\na@b.com k1\nOpenRouter:\nb@c.com k2\nElevenLabs Keys\nd@e.com k3\nGoogle Gemini\nf@g.com k4\n"
	res := ParseTXT(input)
	if len(res.Records) != 4 {
		t.Fatalf("records = %d, want 4: %+v", len(res.Records), res.Records)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	if len(res.NewProviders) != 0 {
		t.Fatalf("new providers = %d, want 0: %+v", len(res.NewProviders), res.NewProviders)
	}
	providers := []string{}
	for _, r := range res.Records {
		providers = append(providers, r.Provider)
	}
	want := []string{"Gemini", "OpenRouter", "ElevenLabs", "Google Gemini"}
	for i := range want {
		if providers[i] != want[i] {
			t.Fatalf("record %d provider = %q, want %q", i, providers[i], want[i])
		}
	}
}

func TestRecordBeforeAnyHeadingFlaggedNotAssigned(t *testing.T) {
	// Fixture, line by line:
	//   1 "orphan@example.com sk-orphan" -> record before any heading
	//   2 "Gemini"                       -> known heading
	//   3 "a@b.com sk-1"                 -> record under Gemini
	// Arithmetic: 2 records; record 0 has no provider and status no_provider,
	// record 1 is Gemini/ok. 0 unmatched, 0 new providers.
	res := ParseTXT("orphan@example.com sk-orphan\nGemini\na@b.com sk-1\n")
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(res.Records))
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	if res.Records[0].Status != StatusNoProvider || res.Records[0].Provider != "" {
		t.Fatalf("orphan record: %+v", res.Records[0])
	}
	if res.Records[1].Provider != "Gemini" {
		t.Fatalf("record after heading: %+v", res.Records[1])
	}
}

func TestOddWhitespaceAndBlankLines(t *testing.T) {
	input := "   \n\nGemini   \n\n   user@example.com    sk-with-spaces-allowed...   \n\t\nOpenAI\n\nother@example.com\tsk-tabbed\n"
	res := ParseTXT(input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %+v", res.Records)
	}
	if res.Records[0].Key != "sk-with-spaces-allowed..." {
		t.Fatalf("key = %q", res.Records[0].Key)
	}
	if res.Records[1].Key != "sk-tabbed" || res.Records[1].Provider != "OpenAI" {
		t.Fatalf("record 1 = %+v", res.Records[1])
	}
}

func TestMixedCaseHeadings(t *testing.T) {
	// Fixture, line by line:
	//   1 "GEMINI"     -> known heading, case-insensitive -> Gemini
	//   2 "a@b.com k1" -> record under Gemini
	//   3 "oPeNrOuTeR" -> known heading, case-insensitive -> OpenRouter
	//   4 "b@c.com k2" -> record under OpenRouter
	//   5 "Anthropic"  -> known heading
	//   6 "c@d.com k3" -> record under Anthropic
	// Arithmetic: 3 records, 0 unmatched, 0 new providers.
	res := ParseTXT("GEMINI\na@b.com k1\noPeNrOuTeR\nb@c.com k2\nAnthropic\nc@d.com k3\n")
	if len(res.Records) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(res.Records), res.Records)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	if len(res.NewProviders) != 0 {
		t.Fatalf("new providers = %d, want 0: %+v", len(res.NewProviders), res.NewProviders)
	}
	want := []string{"Gemini", "OpenRouter", "Anthropic"}
	for i, r := range res.Records {
		if r.Provider != want[i] {
			t.Fatalf("record %d provider = %q, want %q", i, r.Provider, want[i])
		}
	}
}

func TestPunctuationInKeysPreserved(t *testing.T) {
	res := ParseTXT("OpenAI\na@b.com sk-proj_AbC123!@#$%^&*()_+-=[]{}|;:,.<>?\n")
	if len(res.Records) != 1 {
		t.Fatalf("records = %+v", res.Records)
	}
	if res.Records[0].Key != "sk-proj_AbC123!@#$%^&*()_+-=[]{}|;:,.<>?" {
		t.Fatalf("key = %q", res.Records[0].Key)
	}
}

func TestCustomProvidersRecognized(t *testing.T) {
	res := ParseTXT("MyCustomAPI\na@b.com k1\n", "MyCustomAPI")
	if len(res.Records) != 1 || res.Records[0].Provider != "MyCustomAPI" {
		t.Fatalf("custom provider: %+v", res.Records)
	}
}

func TestUnrecognizedHeadingIsCandidateProvider(t *testing.T) {
	input := "Gemini\na@b.com k1\nTotallyUnknownThing\nb@c.com k2\n"
	res := ParseTXT(input)
	if len(res.NewProviders) != 1 || res.NewProviders[0].Name != "TotallyUnknownThing" {
		t.Fatalf("new providers = %+v", res.NewProviders)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unexpected unmatched: %+v", res.Unmatched)
	}
	want := []struct {
		email, provider string
	}{
		{"a@b.com", "Gemini"},
		{"b@c.com", "TotallyUnknownThing"},
	}
	if len(res.Records) != len(want) {
		t.Fatalf("records = %d, want %d: %+v", len(res.Records), len(want), res.Records)
	}
	for i, w := range want {
		r := res.Records[i]
		if r.Email != w.email || r.Provider != w.provider || r.Status != StatusOK {
			t.Errorf("record %d = %+v, want (%q, %q, ok)", i, r, w.email, w.provider)
		}
	}
	if len(res.NewProviders[0].Records) != 1 || res.NewProviders[0].Records[0].Email != "b@c.com" {
		t.Fatalf("new provider records = %+v", res.NewProviders[0].Records)
	}
}

func TestMalformedRecordKept(t *testing.T) {
	res := ParseTXT("Gemini\nnot-an-email but has @ sign\na@b.com k1\n")
	if len(res.Unmatched) != 1 || res.Unmatched[0].Reason != "malformed record" {
		t.Fatalf("unmatched = %+v", res.Unmatched)
	}
	if len(res.Records) != 1 || res.Records[0].Provider != "Gemini" {
		t.Fatalf("records = %+v", res.Records)
	}
}

// TestFiveProviderFileThreeUnknown mirrors the R4 acceptance case: a file
// with five provider headings, three of which are not in the built-in list.
// Every record must end up assigned to a provider, and the three unknown
// headings must come back as new-provider candidates, not unmatched lines.
func TestFiveProviderFileThreeUnknown(t *testing.T) {
	input := "Gemini API Key\n" +
		"a@example.com AQ.aaa\n" +
		"b@example.com AQ.bbb\n" +
		"OpenRouter:\n" +
		"c@example.com sk-or-1\n" +
		"ElevenLabs Keys\n" +
		"d@example.com sk-el-1\n" +
		"d@example.com sk-el-2\n" +
		"MyNewProvider\n" +
		"e@example.com sk-new-1\n" +
		"AnotherNewOne:\n" +
		"f@example.com sk-new-2\n" +
		"ThirdUnknown\n" +
		"g@example.com sk-new-3\n"
	res := ParseTXT(input)

	if len(res.Unmatched) != 0 {
		t.Fatalf("unexpected unmatched lines: %+v", res.Unmatched)
	}
	if len(res.Records) != 8 {
		t.Fatalf("records = %d, want 8: %+v", len(res.Records), res.Records)
	}
	wantProvider := []string{
		"Gemini", "Gemini",
		"OpenRouter",
		"ElevenLabs", "ElevenLabs",
		"MyNewProvider",
		"AnotherNewOne",
		"ThirdUnknown",
	}
	for i, want := range wantProvider {
		if res.Records[i].Provider != want || res.Records[i].Status != StatusOK {
			t.Errorf("record %d = (%q, %q), want (%q, ok)", i, res.Records[i].Provider, res.Records[i].Status, want)
		}
	}

	if len(res.NewProviders) != 3 {
		t.Fatalf("new providers = %d, want 3: %+v", len(res.NewProviders), res.NewProviders)
	}
	wantNew := []string{"MyNewProvider", "AnotherNewOne", "ThirdUnknown"}
	for i, want := range wantNew {
		np := res.NewProviders[i]
		if np.Name != want {
			t.Errorf("new provider %d = %q, want %q", i, np.Name, want)
		}
		if len(np.Records) == 0 {
			t.Errorf("new provider %q has no grouped records", np.Name)
		}
		for _, r := range np.Records {
			if r.Provider != want {
				t.Errorf("grouped record provider = %q, want %q", r.Provider, want)
			}
		}
	}
}

// TestHeadingTrailingWordsAndAllCaps covers R4 case (a): trailing words
// ("API Key", "Keys") and ALL CAPS headings resolve to the canonical known
// provider names.
func TestHeadingTrailingWordsAndAllCaps(t *testing.T) {
	// Fixture, line by line:
	//   1 "Gemini API Key"     -> trailing words stripped -> Gemini
	//   2 "a@b.com k1"         -> record under Gemini
	//   3 "ELEVENLABS"         -> case-insensitive match -> ElevenLabs
	//   4 "b@c.com k2"         -> record under ElevenLabs
	//   5 "OpenRouter:"        -> trailing colon stripped -> OpenRouter
	//   6 "c@d.com k3"         -> record under OpenRouter
	//   7 "Google Gemini Keys" -> trailing words stripped -> Google Gemini
	//   8 "d@e.com k4"         -> record under Google Gemini
	// Arithmetic: 4 records, 0 unmatched, 0 new providers.
	input := "Gemini API Key\na@b.com k1\nELEVENLABS\nb@c.com k2\nOpenRouter:\nc@d.com k3\nGoogle Gemini Keys\nd@e.com k4\n"
	res := ParseTXT(input)
	if len(res.Records) != 4 {
		t.Fatalf("records = %d, want 4: %+v", len(res.Records), res.Records)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	if len(res.NewProviders) != 0 {
		t.Fatalf("new providers = %d, want 0: %+v", len(res.NewProviders), res.NewProviders)
	}
	want := []struct{ email, provider string }{
		{"a@b.com", "Gemini"},
		{"b@c.com", "ElevenLabs"},
		{"c@d.com", "OpenRouter"},
		{"d@e.com", "Google Gemini"},
	}
	for i, w := range want {
		if res.Records[i].Email != w.email || res.Records[i].Provider != w.provider {
			t.Errorf("record %d = (%q, %q), want (%q, %q)", i, res.Records[i].Email, res.Records[i].Provider, w.email, w.provider)
		}
		if res.Records[i].Status != StatusOK {
			t.Errorf("record %d status = %q, want ok", i, res.Records[i].Status)
		}
	}
}

// TestHTTPHeaderLinesAreNotProviders covers R4 case (d): request/header lines
// are unrecognized lines, never provider headings and never records.
func TestHTTPHeaderLinesAreNotProviders(t *testing.T) {
	// Fixture, line by line:
	//   1 "Gemini"                            -> known heading
	//   2 "a@b.com AIzaSyD-1234567890abc"     -> record under Gemini
	//   3 "Content-Type: application/json"    -> contains "/", unrecognized
	//   4 "application/json"                  -> contains "/", unrecognized
	//   5 "HTTP-Referer: https://example.com" -> contains "http", unrecognized
	//   6 "Model ID: gpt-4"                   -> "Name: value" pair, unrecognized
	//   7 "OpenRouter:"                       -> known heading
	//   8 "b@c.com sk-or-1234567890abcdef"    -> record under OpenRouter
	// Arithmetic: 2 records, 4 unmatched, 0 new providers.
	input := "Gemini\na@b.com AIzaSyD-1234567890abcdefghij\nContent-Type: application/json\napplication/json\nHTTP-Referer: https://example.com\nModel ID: gpt-4\nOpenRouter:\nb@c.com sk-or-1234567890abcdef\n"
	res := ParseTXT(input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(res.Records), res.Records)
	}
	if len(res.Unmatched) != 4 {
		t.Fatalf("unmatched = %d, want 4: %+v", len(res.Unmatched), res.Unmatched)
	}
	if len(res.NewProviders) != 0 {
		t.Fatalf("new providers = %d, want 0: %+v", len(res.NewProviders), res.NewProviders)
	}
	if res.Records[0].Provider != "Gemini" || res.Records[1].Provider != "OpenRouter" {
		t.Fatalf("records = %+v", res.Records)
	}
}

// TestKeyOnlyLineUnderHeadingNeedsAttention covers R4 case (e): a key-only
// line under a heading becomes a record with an empty email that needs
// attention, so the user must fill the email in before it is useful.
func TestKeyOnlyLineUnderHeadingNeedsAttention(t *testing.T) {
	// Fixture, line by line:
	//   1 "Jina.ai"                -> unknown heading candidate
	//   2 "jina_FAKE00000000001" -> key-only line, no email
	//   3 "HuggingFace"            -> unknown heading candidate
	//   4 "hf_FAKE00000000001"      -> key-only line, no email
	// Arithmetic: 2 records, both with empty email and status needs_attention;
	// 2 new providers (Jina.ai, HuggingFace); 0 unmatched.
	input := "Jina.ai\njina_FAKE00000000001\nHuggingFace\nhf_FAKE00000000001\n"
	res := ParseTXT(input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(res.Records), res.Records)
	}
	if len(res.NewProviders) != 2 {
		t.Fatalf("new providers = %d, want 2: %+v", len(res.NewProviders), res.NewProviders)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	wantProvider := []string{"Jina.ai", "HuggingFace"}
	for i, r := range res.Records {
		if r.Email != "" {
			t.Errorf("record %d email = %q, want empty", i, r.Email)
		}
		if r.Status != StatusNeedsAttention {
			t.Errorf("record %d status = %q, want needs_attention", i, r.Status)
		}
		if r.Provider != wantProvider[i] {
			t.Errorf("record %d provider = %q, want %q", i, r.Provider, wantProvider[i])
		}
	}
}

// TestRealWorldHeadings covers the headings from the user's real file: a typo
// is offered as a new provider (never silently corrected), an ALL CAPS name
// matches case-insensitively, and dotted/camel-case names are candidates.
func TestRealWorldHeadings(t *testing.T) {
	// Fixture, line by line:
	//   1 "Gemmini API Keys:"         -> typo, trailing words stripped -> new provider "Gemmini"
	//   2 "a@b.com AIzaSyD-1234..."   -> record under Gemmini
	//   3 "OpenRouter"               -> known heading
	//   4 "b@c.com sk-or-1234..."    -> record under OpenRouter
	//   5 "ELEVENLABS"               -> case-insensitive match -> ElevenLabs
	//   6 "d@e.com sk-el-1234..."    -> record under ElevenLabs
	//   7 "Jina.ai"                  -> new provider
	//   8 "jina_FAKE00000000001"    -> key-only record, empty email
	//   9 "HuggingFace"              -> new provider
	//  10 "hf_FAKE00000000001"        -> key-only record, empty email
	// Arithmetic: 5 records, 3 new providers (Gemmini, Jina.ai, HuggingFace),
	// 0 unmatched.
	input := "Gemmini API Keys:\na@b.com AIzaSyD-1234567890abcdefghij\nOpenRouter\nb@c.com sk-or-1234567890abcdef\nELEVENLABS\nd@e.com sk-el-1234567890abcdef\nJina.ai\njina_FAKE00000000001\nHuggingFace\nhf_FAKE00000000001\n"
	res := ParseTXT(input)
	if len(res.Records) != 5 {
		t.Fatalf("records = %d, want 5: %+v", len(res.Records), res.Records)
	}
	if len(res.NewProviders) != 3 {
		t.Fatalf("new providers = %d, want 3: %+v", len(res.NewProviders), res.NewProviders)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	wantProvider := []string{"Gemmini", "OpenRouter", "ElevenLabs", "Jina.ai", "HuggingFace"}
	for i, want := range wantProvider {
		if res.Records[i].Provider != want {
			t.Errorf("record %d provider = %q, want %q", i, res.Records[i].Provider, want)
		}
	}
	wantNew := []string{"Gemmini", "Jina.ai", "HuggingFace"}
	for i, want := range wantNew {
		if res.NewProviders[i].Name != want {
			t.Errorf("new provider %d = %q, want %q", i, res.NewProviders[i].Name, want)
		}
	}
}

// TestSuggestionWithinTwoEdits covers item 11: a heading that is not a known
// provider but is within two edits of one is offered as a suggestion, and a
// heading far from every known provider is not. The suggestion is never
// applied silently; the record keeps the parsed provider until the user
// accepts it in the review step.
func TestSuggestionWithinTwoEdits(t *testing.T) {
	// Fixture, line by line:
	//   1 "Gemmini API Keys:"       -> trailing words stripped -> "Gemmini"
	//   2 "a@b.com AIzaSyD-1234..." -> record under Gemmini
	//   3 "Zephyr"                  -> unknown heading, far from every known name
	//   4 "b@c.com sk-1234567890"   -> record under Zephyr
	// Arithmetic: 2 records, 2 new providers, 0 unmatched. "Gemmini" is 1
	// edit from "Gemini", so it suggests "Gemini"; "Zephyr" is 5+ edits from
	// every known name, so it has no suggestion.
	input := "Gemmini API Keys:\na@b.com AIzaSyD-1234567890abcdefghij\nZephyr\nb@c.com sk-1234567890abcdef\n"
	res := ParseTXT(input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(res.Records), res.Records)
	}
	if len(res.NewProviders) != 2 {
		t.Fatalf("new providers = %d, want 2: %+v", len(res.NewProviders), res.NewProviders)
	}
	if len(res.Unmatched) != 0 {
		t.Fatalf("unmatched = %d, want 0: %+v", len(res.Unmatched), res.Unmatched)
	}
	if res.NewProviders[0].Name != "Gemmini" || res.NewProviders[0].Suggestion != "Gemini" {
		t.Fatalf("Gemmini candidate = %+v, want name Gemmini suggestion Gemini", res.NewProviders[0])
	}
	if res.NewProviders[1].Name != "Zephyr" || res.NewProviders[1].Suggestion != "" {
		t.Fatalf("Zephyr candidate = %+v, want name Zephyr and no suggestion", res.NewProviders[1])
	}
	// The suggestion must not be applied silently.
	if res.Records[0].Provider != "Gemmini" {
		t.Fatalf("record provider = %q, want Gemmini (uncorrected)", res.Records[0].Provider)
	}
}

// TestRealFileHeadingLines covers R5 item 6 with the exact lines from the
// user's real file: request/header lines create no providers, while a heading
// followed by a key-only line does.
func TestRealFileHeadingLines(t *testing.T) {
	// Fixture, line by line:
	//   1 "Content-Type"               -> heading candidate
	//   2 "application/json"           -> unrecognized (slash): 1 not confirmed
	//   3 "Authorization"              -> heading candidate
	//   4 "Bearer $OPENROUTER_API_KEY" -> unrecognized ($): 3 not confirmed
	//   5 "Model"                      -> heading candidate
	//   6 "openrouter/free"           -> unrecognized (slash): 5 not confirmed
	//   7 "ENDPOINT:"                  -> heading candidate
	//   8 "https://api.example.com/v1" -> unrecognized (http): 7 not confirmed
	//   9 "Jina.ai"                    -> heading candidate
	//  10 "jina_FAKE00000000001"      -> key-only record: 9 confirmed
	//  11 "HuggingFace"                -> heading candidate
	//  12 "hf_FAKE00000000001"          -> key-only record: 11 confirmed
	// Arithmetic: 2 records (empty email, needs_attention), 2 new providers
	// (Jina.ai, HuggingFace), 8 unmatched lines (1-8), 0 other providers.
	input := "Content-Type\napplication/json\nAuthorization\nBearer $OPENROUTER_API_KEY\nModel\nopenrouter/free\nENDPOINT:\nhttps://api.example.com/v1\nJina.ai\njina_FAKE00000000001\nHuggingFace\nhf_FAKE00000000001\n"
	res := ParseTXT(input)
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(res.Records), res.Records)
	}
	if len(res.NewProviders) != 2 {
		t.Fatalf("new providers = %d, want 2: %+v", len(res.NewProviders), res.NewProviders)
	}
	if len(res.Unmatched) != 8 {
		t.Fatalf("unmatched = %d, want 8: %+v", len(res.Unmatched), res.Unmatched)
	}
	wantProvider := []string{"Jina.ai", "HuggingFace"}
	for i, want := range wantProvider {
		if res.NewProviders[i].Name != want {
			t.Errorf("new provider %d = %q, want %q", i, res.NewProviders[i].Name, want)
		}
		if res.Records[i].Provider != want || res.Records[i].Email != "" || res.Records[i].Status != StatusNeedsAttention {
			t.Errorf("record %d = %+v, want provider %q, empty email, needs_attention", i, res.Records[i], want)
		}
	}
	for _, u := range res.Unmatched {
		if u.Reason != "unrecognized line" {
			t.Errorf("unmatched line %d reason = %q, want unrecognized line", u.Line, u.Reason)
		}
	}
}

// TestHeadingNeedsFollowingRecord pins the heading rule: a no-email line is a
// provider heading only if at least one record follows it before the next
// heading or unrecognized line.
func TestHeadingNeedsFollowingRecord(t *testing.T) {
	// Fixture, line by line:
	//   1 "Orphan"           -> heading candidate, next line unrecognized -> not a heading
	//   2 "application/json" -> unrecognized
	//   3 "Parent"           -> heading candidate, next line a record -> heading
	//   4 "a@b.com sk-1"     -> record under Parent
	// Arithmetic: 1 record under Parent, 1 new provider, 2 unmatched.
	res := ParseTXT("Orphan\napplication/json\nParent\na@b.com sk-1\n")
	if len(res.NewProviders) != 1 || res.NewProviders[0].Name != "Parent" {
		t.Fatalf("new providers = %+v, want only Parent", res.NewProviders)
	}
	if len(res.Unmatched) != 2 {
		t.Fatalf("unmatched = %d, want 2: %+v", len(res.Unmatched), res.Unmatched)
	}
	if len(res.Records) != 1 || res.Records[0].Provider != "Parent" {
		t.Fatalf("records = %+v, want one under Parent", res.Records)
	}

	// A heading candidate at end of file with no following record is not a
	// provider: 1 record (before any heading), 0 new providers, 1 unmatched.
	res = ParseTXT("a@b.com sk-0\nLonely\n")
	if len(res.NewProviders) != 0 {
		t.Fatalf("new providers = %+v, want 0", res.NewProviders)
	}
	if len(res.Unmatched) != 1 || res.Unmatched[0].Text != "Lonely" {
		t.Fatalf("unmatched = %+v, want only Lonely", res.Unmatched)
	}
	if len(res.Records) != 1 || res.Records[0].Status != StatusNoProvider {
		t.Fatalf("records = %+v, want one no_provider record", res.Records)
	}
}

// TestKeyOnlyTokenRule pins the key-only definition: a single token of at
// least 16 characters from letters, digits, dots, underscores and hyphens,
// with no slash, and at least one digit.
func TestKeyOnlyTokenRule(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"jina_FAKE00000000001", true}, // 21 chars, underscore + digits
		{"hf_FAKE00000000001", true},   // 17 chars
		{"1234567890123456", true},     // exactly 16 digits
		{"AIzaFAKE0001abcdefg", true},  // 19 chars, digits required
		{"abcdefghijklmnop", false},    // exactly 16 letters, no digit
		{"shortkey1234567", false},     // 15 chars
		{"has/slash123456789", false},  // slash
		{"two words 123456789", false}, // spaces
	}
	for _, c := range cases {
		if got := isKeyOnly(c.line); got != c.want {
			t.Errorf("isKeyOnly(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestKeyOnlyTokenNeedsDigit pins the digit requirement: a key-only token
// must contain at least one digit, so an all-letter token of 16+ characters
// is a heading candidate rather than a key.
func TestKeyOnlyTokenNeedsDigit(t *testing.T) {
	if !isKeyOnly("AIzaFAKE0001abcdefg") {
		t.Errorf("isKeyOnly(%q) = false, want true", "AIzaFAKE0001abcdefg")
	}
	if isKeyOnly("TotallyUnknownThing") {
		t.Errorf("isKeyOnly(%q) = true, want false (no digit)", "TotallyUnknownThing")
	}

	// TotallyUnknownThing is a heading candidate: a record after it makes it
	// a new provider heading, not a key-only record.
	res := ParseTXT("TotallyUnknownThing\na@b.com k1\n")
	if len(res.NewProviders) != 1 || res.NewProviders[0].Name != "TotallyUnknownThing" {
		t.Fatalf("new providers = %+v, want TotallyUnknownThing as a heading candidate", res.NewProviders)
	}
	if len(res.Records) != 1 || res.Records[0].Provider != "TotallyUnknownThing" {
		t.Fatalf("records = %+v, want one under TotallyUnknownThing", res.Records)
	}

	// AIzaFAKE0001abcdefg is a key-only token: under a heading it becomes a
	// needs-attention record with an empty email.
	res = ParseTXT("Gemini\nAIzaFAKE0001abcdefg\n")
	if len(res.Records) != 1 || res.Records[0].Key != "AIzaFAKE0001abcdefg" || res.Records[0].Email != "" || res.Records[0].Status != StatusNeedsAttention {
		t.Fatalf("records = %+v, want one key-only needs_attention record under Gemini", res.Records)
	}
}

// TestLevenshtein pins the edit-distance arithmetic by hand.
func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"Gemini", "Gemini", 0},  // identical
		{"Gemmini", "Gemini", 1}, // one extra m
		{"gemmini", "Gemini", 1}, // case-insensitive
		{"OpenRouter", "OpenAI", 6},
		{"", "abc", 3}, // three insertions
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
