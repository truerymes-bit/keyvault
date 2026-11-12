// Package web embeds the frontend so KeyVault ships as a single binary.
package web

import "embed"

// FS holds the static frontend files.
//
//go:embed index.html css js all:assets
var FS embed.FS
