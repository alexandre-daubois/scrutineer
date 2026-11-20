package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Operator assessments of a candidate observation.
const (
	CandidateConfirmed     = "confirmed"
	CandidateFalsePositive = "false_positive"
	CandidateUnsure        = "unsure"
)

// Operator decisions on a candidate scan's configuration.
const (
	ExperimentAdopt  = "adopt"
	ExperimentReject = "reject"
)

// CandidateObservation is one finding a candidate scan reported. It never
// becomes a canonical finding: the comparison matches it to the baseline by
// Fingerprint, which is computed under the baseline scan's skill name so a
// candidate running another skill still lines up. Its text and Evidence are
// untrusted model output, stored and shown as data only.
type CandidateObservation struct {
	ID              uint   `gorm:"primarykey"`
	ScanID          uint   `gorm:"not null;uniqueIndex:idx_candidate_observation_scan,priority:1"`
	RepositoryID    uint   `gorm:"index;not null"`
	ReportFindingID string // the finding's id inside the candidate report, e.g. F1
	Fingerprint     string `gorm:"not null;uniqueIndex:idx_candidate_observation_scan,priority:2"`
	Title           string
	Severity        string
	Confidence      string
	CWE             string
	Location        string
	Reachability    string
	Rating          string `gorm:"type:text"`
	Evidence        string `gorm:"type:text"` // JSON object of the unpromoted evidence fields
	// Assessment is the operator's verdict (confirmed, false_positive,
	// unsure), empty until one is recorded.
	Assessment     string
	AssessmentNote string `gorm:"type:text"`
	// EffortMinutes is the analyst time recorded with the assessment. Nil
	// means none was recorded, which the comparison shows as unavailable.
	EffortMinutes *int
	AssessedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ExperimentDecision is an operator's recorded decision on the configuration a
// candidate scan ran with. Recording one changes no setting: ordinary scans
// keep their model, effort and skill until the operator changes them.
type ExperimentDecision struct {
	ID              uint `gorm:"primarykey"`
	RepositoryID    uint `gorm:"index;not null"`
	CandidateScanID uint `gorm:"index;not null"`
	Experiment      string
	Decision        string
	Note            string `gorm:"type:text"`
	CreatedAt       time.Time
}

// IsCandidate reports whether the scan is a candidate run, whose output is
// kept apart from the repository's findings.
func (s Scan) IsCandidate() bool {
	return s.CandidateOfScanID != nil
}

// ProductionScans excludes candidate scans from q. A candidate's results do
// not describe the repository, so they never stand in for its latest scan,
// satisfy a prerequisite or serve as a diff baseline.
func ProductionScans(q *gorm.DB) *gorm.DB {
	return q.Where("candidate_of_scan_id IS NULL")
}

// CandidateObservationFromFinding builds the observation row for a candidate
// scan reporting f. f.Fingerprint must already be set.
func CandidateObservationFromFinding(scan *Scan, f *Finding) CandidateObservation {
	return CandidateObservation{
		ScanID:          scan.ID,
		RepositoryID:    scan.RepositoryID,
		ReportFindingID: f.FindingID,
		Fingerprint:     f.Fingerprint,
		Title:           f.Title,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		CWE:             f.CWE,
		Location:        f.Location,
		Reachability:    f.Reachability,
		Rating:          f.Rating,
		Evidence:        observationEvidence(f),
	}
}

// RecordCandidateObservations upserts each observation on its (scan,
// fingerprint) pair. A repeat write replaces the reported content so the
// final report wins over a streamed preview, and leaves any assessment alone.
func RecordCandidateObservations(gdb *gorm.DB, obs ...CandidateObservation) error {
	if len(obs) == 0 {
		return nil
	}
	return gdb.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "scan_id"}, {Name: "fingerprint"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"report_finding_id", "title", "severity", "confidence", "cwe", "location",
			"reachability", "rating", "evidence", "updated_at",
		}),
	}).CreateInBatches(&obs, observationBatchSize).Error
}
