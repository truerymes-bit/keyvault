package importer

import "testing"

func TestCSVHeaderless(t *testing.T) {
	in := "a@b.com,sk-111\nc@d.com,sk-222,OpenAI\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("records = %+v", res.Records)
	}
	if res.Records[0].Email != "a@b.com" || res.Records[0].Key != "sk-111" {
		t.Fatalf("record 0 = %+v", res.Records[0])
	}
	if res.Records[0].Status != StatusNoProvider {
		t.Fatalf("record 0 status = %q", res.Records[0].Status)
	}
	if res.Records[1].Provider != "OpenAI" || res.Records[1].Status != StatusOK {
		t.Fatalf("record 1 = %+v", res.Records[1])
	}
}

func TestCSVWithHeader(t *testing.T) {
	in := "email,api_key,provider\na@b.com,sk-111,Gemini\nc@d.com,sk-222,OpenRouter\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("records = %+v", res.Records)
	}
	if res.Records[0].Provider != "Gemini" || res.Records[1].Provider != "OpenRouter" {
		t.Fatalf("records = %+v", res.Records)
	}
}

func TestCSVHeaderColumnOrder(t *testing.T) {
	in := "provider,email,notes_col_ignored,key\nGemini,a@b.com,whatever,sk-111\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %+v", res.Records)
	}
	got := res.Records[0]
	if got.Email != "a@b.com" || got.Key != "sk-111" || got.Provider != "Gemini" {
		t.Fatalf("record = %+v", got)
	}
}

func TestCSVQuotedFields(t *testing.T) {
	in := "email,key\n\"a@b.com\",\"sk-with,comma-and espaços\"\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %+v", res.Records)
	}
	if res.Records[0].Key != "sk-with,comma-and espaços" {
		t.Fatalf("key = %q", res.Records[0].Key)
	}
}

func TestCSVQuotedQuotes(t *testing.T) {
	in := "email,key\na@b.com,\"sk-say-\"\"hi\"\"-ok\"\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records[0].Key != `sk-say-"hi"-ok` {
		t.Fatalf("key = %q", res.Records[0].Key)
	}
}

func TestCSVMalformedRowsKept(t *testing.T) {
	in := "email,key\nno-at-sign,sk-111\na@b.com,sk-222\n,sk-333\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 || res.Records[0].Key != "sk-222" {
		t.Fatalf("records = %+v", res.Records)
	}
	if len(res.Unmatched) != 2 {
		t.Fatalf("unmatched = %+v", res.Unmatched)
	}
}

func TestCSVHeaderWithoutKeyColumn(t *testing.T) {
	// A row that looks like a header but lacks a key column is an error,
	// never silently parsed as data.
	in := "email,provider\na@b.com,Gemini\n"
	_, err := ParseCSV(in)
	if err == nil {
		t.Fatal("expected error for header without key column")
	}
}

func TestCSVBlankLinesSkipped(t *testing.T) {
	in := "\nemail,key\n\na@b.com,sk-111\n,,\n"
	res, err := ParseCSV(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %+v", res.Records)
	}
}

func TestCSVEmpty(t *testing.T) {
	res, err := ParseCSV("")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 0 || len(res.Unmatched) != 0 {
		t.Fatalf("empty input: %+v", res)
	}
}
