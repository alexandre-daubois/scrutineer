package db

import (
	"testing"

	"scrutineer/internal/testutil"
)

// TestPostgresFindingSynthesisUpsert pins that a second write for the same scan replaces its row on PostgreSQL.
func TestPostgresFindingSynthesisUpsert(t *testing.T) {
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatalf("OpenBackend postgres: %v", err)
	}
	closePostgres(t, gdb)

	repo := Repository{URL: "https://example.com/pg/syntheses", Name: "pg-syntheses"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone, SkillName: "synthesize"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "f"}
	if err := gdb.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	for _, report := range []string{`{"summary":"first"}`, `{"summary":"second"}`} {
		if err := RecordFindingSynthesis(gdb, &FindingSynthesis{FindingID: f.ID, ScanID: scan.ID, RepositoryID: repo.ID, Report: report, Sources: `{"R1":1}`}); err != nil {
			t.Fatalf("record %s: %v", report, err)
		}
	}
	var rows []FindingSynthesis
	if err := gdb.Where("scan_id = ?", scan.ID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Report != `{"summary":"second"}` {
		t.Fatalf("rows = %+v", rows)
	}
}
