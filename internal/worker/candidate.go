package worker

import (
	"encoding/json"
	"fmt"

	"scrutineer/internal/db"
)

// candidateBaseline loads the ordinary scan a candidate is compared against.
func (w *Worker) candidateBaseline(scan *db.Scan) (db.Scan, error) {
	var baseline db.Scan
	if err := w.DB.Select("id", "skill_name", "ref", "commit", "sub_path", "scope_mode", "staged_inputs_sha256").First(&baseline, *scan.CandidateOfScanID).Error; err != nil {
		return db.Scan{}, fmt.Errorf("load baseline scan %d: %w", *scan.CandidateOfScanID, err)
	}
	return baseline, nil
}

// checkCandidateInputs fails a candidate whose source commit or scope differs
// from what its baseline ran against, so the comparison never reads a change of
// inputs as a change of configuration. The scope is compared with the baseline
// row, which records a hard scope its run widened to soft. The scan config,
// threat model and analyst feedback are checked once staged, by
// pinStagedInputs.
func (w *Worker) checkCandidateInputs(scan *db.Scan) error {
	baseline, err := w.candidateBaseline(scan)
	if err != nil {
		return err
	}
	if scan.Commit != baseline.Commit {
		return fmt.Errorf("candidate source commit %q differs from baseline scan #%d commit %q", scan.Commit, baseline.ID, baseline.Commit)
	}
	if scan.SubPath != baseline.SubPath || scan.ScopeMode != baseline.ScopeMode {
		return fmt.Errorf("candidate scope %q (%s) differs from baseline scan #%d scope %q (%s)", scan.SubPath, scan.ScopeMode, baseline.ID, baseline.SubPath, baseline.ScopeMode)
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

// pinStagedInputs records a digest of the scan config, threat model and
// analyst feedback staged for a scan tied to an experiment, and fails a
// candidate whose digest differs from its baseline's. It is taken from the run
// itself, so a baseline resumed under an edited scan config records the one it
// finished with, and the threat model and feedback are filtered against live
// review state, which the raw repository text does not show.
func (w *Worker) pinStagedInputs(scan *db.Scan, model string, feedback []db.FindingFeedback) error {
	if scan.Experiment == "" {
		return nil
	}
	digest, err := stagedInputsDigest(scan.Repository.ScanConfig, model, feedback)
	if err != nil {
		return err
	}
	scan.StagedInputsSHA256 = digest
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("staged_inputs_sha256", digest).Error; err != nil {
		return fmt.Errorf("record staged inputs digest: %w", err)
	}
	if !scan.IsCandidate() {
		return nil
	}
	baseline, err := w.candidateBaseline(scan)
	if err != nil {
		return err
	}
	if baseline.StagedInputsSHA256 != digest {
		return fmt.Errorf("the scan config, threat model or analyst feedback staged for this candidate differs from what baseline scan #%d ran with", baseline.ID)
	}
	return nil
}

// stagedInputsDigest is "" when nothing was staged, like textDigest.
func stagedInputsDigest(scanConfig, model string, feedback []db.FindingFeedback) (string, error) {
	if scanConfig == "" && model == "" && len(feedback) == 0 {
		return "", nil
	}
	staged, err := json.Marshal(struct {
		ScanConfig  string               `json:"scan_config"`
		ThreatModel string               `json:"threat_model"`
		Feedback    []db.FindingFeedback `json:"feedback"`
	}{scanConfig, model, feedback})
	if err != nil {
		return "", fmt.Errorf("digest staged inputs: %w", err)
	}
	return textDigest(string(staged)), nil
}
