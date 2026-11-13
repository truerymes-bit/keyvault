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
	input := "Gemini API Key\na@b.com k1\nOpenRouter:\nb@c.com k2\nElevenLabs Keys\nd@e.com k3\nGoogle Gemini\nf@g.com k4\n"
	res := ParseTXT(input)
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
	res := ParseTXT("orphan@example.com sk-orphan\nGemini\na@b.com sk-1\n")
	if len(res.Records) != 2 {
		t.Fatalf("records = %d", len(res.Records))
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
	res := ParseTXT("GEMINI\na@b.com k1\noPeNrOuTeR\nb@c.com k2\nAnthropic\nc@d.com k3\n")
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
