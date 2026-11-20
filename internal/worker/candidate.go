package worker

import (
	"encoding/json"
	"fmt"

	"scrutineer/internal/db"
)

// candidateBaseline loads the ordinary scan a candidate is compared against.
func (w *Worker) candidateBaseline(scan *db.Scan) (db.Scan, error) {
	var baseline db.Scan
	if err := w.DB.Select("id", "skill_name", "ref", "commit", "recipe").First(&baseline, *scan.CandidateOfScanID).Error; err != nil {
		return db.Scan{}, fmt.Errorf("load baseline scan %d: %w", *scan.CandidateOfScanID, err)
	}
	return baseline, nil
}

// checkCandidateInputs fails a candidate whose source commit, threat model or
// scan config differs from what its baseline ran against, so the comparison
// never reads a change of inputs as a change of configuration.
func (w *Worker) checkCandidateInputs(scan *db.Scan) error {
	baseline, err := w.candidateBaseline(scan)
	if err != nil {
		return err
	}
	if scan.Commit != baseline.Commit {
		return fmt.Errorf("candidate source commit %q differs from baseline scan #%d commit %q", scan.Commit, baseline.ID, baseline.Commit)
	}
	var want, got ScanRecipe
	if err := json.Unmarshal([]byte(baseline.Recipe), &want); err != nil {
		return fmt.Errorf("baseline scan #%d has no readable recipe: %w", baseline.ID, err)
	}
	if err := json.Unmarshal([]byte(scan.Recipe), &got); err != nil {
		return fmt.Errorf("candidate scan #%d has no readable recipe: %w", scan.ID, err)
	}
	if got.ThreatModelSHA256 != want.ThreatModelSHA256 {
		return fmt.Errorf("repository threat model changed since baseline scan #%d ran", baseline.ID)
	}
	if got.ScanConfigSHA256 != want.ScanConfigSHA256 {
		return fmt.Errorf("repository scan config changed since baseline scan #%d ran", baseline.ID)
	}
	return nil
}

// fingerprintSkillName is the skill name a scan's finding fingerprints are
// computed under. A candidate uses its baseline's, so the same finding lines
// up across the pair even when the candidate runs another skill.
func (w *Worker) fingerprintSkillName(scan *db.Scan) (string, error) {
	if !scan.IsCandidate() {
		return scan.SkillName, nil
	}
	baseline, err := w.candidateBaseline(scan)
	if err != nil {
		return "", err
	}
	return baseline.SkillName, nil
}

// parseCandidateOutput records a candidate's findings as candidate
// observations. A candidate never writes, re-observes or retracts canonical
// findings, and fail_on, which gates ordinary runs, does not apply to it.
func (w *Worker) parseCandidateOutput(skill *db.Skill, scan *db.Scan, report string, emit func(Event)) error {
	if skill.OutputKind != "findings" {
		return fmt.Errorf("candidate scans only record findings, skill %q writes %q", skill.Name, skill.OutputKind)
	}
	fingerprintSkill, err := w.fingerprintSkillName(scan)
	if err != nil {
		return err
	}
	findings, err := w.reportFindings(skill, scan, report, fingerprintSkill, emit)
	if err != nil {
		return err
	}
	obs := make([]db.CandidateObservation, 0, len(findings))
	for i := range findings {
		obs = append(obs, db.CandidateObservationFromFinding(scan, &findings[i]))
	}
	if err := db.RecordCandidateObservations(w.DB, obs...); err != nil {
		return fmt.Errorf("record candidate observations: %w", err)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("recorded %d candidate observation(s), repository findings unchanged", len(obs))})
	return nil
}
