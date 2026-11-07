package web

import "github.com/rselbach/scimtest/internal/core"

// saveState seeds a fresh test database with a whole-state snapshot.
// Production code saves one environment at a time; the whole-database write
// is reserved for the legacy migration and these tests.
var saveState = core.SaveState
