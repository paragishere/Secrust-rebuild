package migrations

import "embed"

// FS contains the SQL migration files embedded into the application.
//
//go:embed *.sql
var FS embed.FS
