package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FindingSynthesis is one synthesize scan's combination of a finding's
// observations. Report is the host-validated model output, which cites
// observations by neutral label only. Sources maps each label to its
// observation id, so reviewer identity is attached when the row is read.
// Nothing here changes the finding's status, severity or disclosure fields.
type FindingSynthesis struct {
	ID           uint   `gorm:"primarykey"`
	FindingID    uint   `gorm:"index;not null"`
	ScanID       uint   `gorm:"uniqueIndex;not null"`
	RepositoryID uint   `gorm:"index;not null"`
	Report       string `gorm:"type:text"`
	Sources      string `gorm:"type:text"` // JSON object, label -> observation id
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RecordFindingSynthesis upserts the synthesis on its scan, so re-parsing the
// same scan's report replaces it instead of adding a second row.
func RecordFindingSynthesis(gdb *gorm.DB, s *FindingSynthesis) error {
	return gdb.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"finding_id", "repository_id", "report", "sources", "updated_at"}),
	}).Create(s).Error
}
