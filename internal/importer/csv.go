package importer

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// ParseCSV parses a CSV import document into the same Result shape as
// ParseTXT. Columns are either mapped from a header row (recognized when it
// contains both an email and a key-like column name) or assumed positional:
// email, key, optional provider, optional label.
func ParseCSV(input string, customProviders ...string) (*Result, error) {
	r := csv.NewReader(bytes.NewReader([]byte(input)))
	r.FieldsPerRecord = -1 // tolerate ragged rows; validated per record
	r.TrimLeadingSpace = true

	res := &Result{}
	rows := [][]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv: %w", err)
		}
		rows = append(rows, rec)
	}
	if len(rows) == 0 {
		return res, nil
	}

	emailIdx, keyIdx, providerIdx := 0, 1, -1
	start := 0

	header := rows[0]
	if em, ky, ok := detectHeader(header); ok {
		emailIdx, keyIdx = em, ky
		providerIdx = findColumn(header, "provider", "provider_name", "service")
		start = 1
		_ = customProviders // provider names come from the column itself
	} else if findColumn(header, "email", "email_address", "account") >= 0 {
		// Row looks like a header (it has an email column) but no
		// key-like column; treating it as data would be wrong.
		return nil, fmt.Errorf("csv header contains an email column but no key-like column (key, api_key, token)")
	} else {
		// Headerless positional: email, key, optional provider in col 3.
		for _, row := range rows {
			if len(row) >= 3 {
				providerIdx = 2
				break
			}
		}
	}

	for i := start; i < len(rows); i++ {
		lineNo := i + 1
		fields := rows[i]
		if isBlankRow(fields) {
			continue
		}
		get := func(idx int) string {
			if idx < 0 || idx >= len(fields) {
				return ""
			}
			return strings.TrimSpace(fields[idx])
		}
		email, key, provider := get(emailIdx), get(keyIdx), get(providerIdx)
		if email == "" || key == "" || !strings.Contains(email, "@") {
			res.Unmatched = append(res.Unmatched, UnmatchedLine{
				Line:   lineNo,
				Text:   strings.Join(fields, ","),
				Reason: "malformed record",
			})
			continue
		}
		status := StatusOK
		if provider == "" {
			status = StatusNoProvider
		}
		res.Records = append(res.Records, Record{
			Line:     lineNo,
			Email:    email,
			Key:      key,
			Provider: provider,
			Status:   status,
		})
	}
	return res, nil
}

func detectHeader(header []string) (emailIdx, keyIdx int, ok bool) {
	emailIdx, keyIdx = findColumn(header, "email", "email_address", "account"),
		findColumn(header, "key", "api_key", "apikey", "api key", "token")
	if emailIdx >= 0 && keyIdx >= 0 {
		return emailIdx, keyIdx, true
	}
	return 0, 0, false
}

func findColumn(header []string, names ...string) int {
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		for _, n := range names {
			if h == n {
				return i
			}
		}
	}
	return -1
}

func isBlankRow(fields []string) bool {
	for _, f := range fields {
		if strings.TrimSpace(f) != "" {
			return false
		}
	}
	return true
}
