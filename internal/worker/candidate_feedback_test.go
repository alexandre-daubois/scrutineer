package worker

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"scrutineer/internal/db"
)

// A candidate deep dive citing eligible analyst feedback records no confirmation and leaves the threat model alone, while its ordinary baseline at the same commit confirms and promotes.
func TestCandidate_neverConfirmsOrPromotesAnalystFeedback(t *testing.T) {
	p := newPromotionFixture(t, promotionModel)
	p.cite("c1")
	p.cite("c2")
	before := p.model()
	baseline := p.newDiveScan("c3", db.ScanRescanModeDiff, "")
	candidate := &db.Scan{RepositoryID: p.repo.ID, Kind: JobSkill, SkillName: deepDiveSkillName, Commit: "c3",
		RescanMode: db.ScanRescanModeDiff, Experiment: "trial", CandidateOfScanID: &baseline.ID}
	if err := p.w.DB.Create(candidate).Error; err != nil {
		t.Fatal(err)
	}
	skill := &db.Skill{Name: deepDiveSkillName, OutputKind: "findings"}
	report := diveReport("bound holds", `["S1"]`, fmt.Sprintf("[%d]", p.reviewID))

	if err := p.w.parseSkillOutputKind(t.Context(), skill, candidate, report, func(Event) {}); err != nil {
		t.Fatalf("candidate parse: %v", err)
	}
	var n int64
	if err := p.w.DB.Model(&db.FeedbackConfirmation{}).Where("scan_id = ?", candidate.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("candidate recorded %d feedback confirmation(s), want none", n)
	}
	if got := p.model(); got != before {
		t.Errorf("threat model after candidate = %s, want it unchanged", got)
	}

	if err := p.w.parseSkillOutputKind(t.Context(), skill, baseline, report, func(Event) {}); err != nil {
		t.Fatalf("baseline parse: %v", err)
	}
	var c db.FeedbackConfirmation
	if err := p.w.DB.Where("scan_id = ?", baseline.ID).First(&c).Error; err != nil || c.ReviewID != p.reviewID || c.Commit != "c3" {
		t.Fatalf("baseline confirmation = %+v, %v, want review %d at c3", c, err, p.reviewID)
	}
	if len(promotedItems(t, p.model())) != 1 {
		t.Errorf("baseline at the third commit did not promote: %s", p.model())
	}
}

// A candidate's recipe names its experiment, the configuration snapshot and the baseline scan it is compared against.
func TestCandidate_recipeCarriesExperimentAndBaseline(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, candidate := candidatePair(t, w, repo)
	candidate.ExperimentConfig = `{"model":"model-b","effort":"low"}`
	raw, err := buildScanRecipe(candidate, "claude", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Experiment        string          `json:"experiment"`
		ExperimentConfig  json.RawMessage `json:"experiment_config"`
		CandidateOfScanID json.RawMessage `json:"candidate_of_scan_id"`
	}
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Experiment != "trial" {
		t.Errorf("experiment = %q, want trial", got.Experiment)
	}
	if string(got.ExperimentConfig) != candidate.ExperimentConfig {
		t.Errorf("experiment_config = %s, want %s", got.ExperimentConfig, candidate.ExperimentConfig)
	}
	if want := strconv.FormatUint(uint64(baseline.ID), 10); string(got.CandidateOfScanID) != want {
		t.Errorf("candidate_of_scan_id = %s, want %s", got.CandidateOfScanID, want)
	}
}

// An ordinary scan that asked for an experiment records it in its recipe without any candidate_of_scan_id key.
func TestCandidate_ordinaryRecipeOmitsCandidateOfScanID(t *testing.T) {
	w, repo := observationWorker(t)
	baseline, _ := candidatePair(t, w, repo)
	raw, err := buildScanRecipe(baseline, "claude", "", "")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if string(got["experiment"]) != `"trial"` {
		t.Errorf("experiment = %s, want \"trial\"", got["experiment"])
	}
	if v, ok := got["candidate_of_scan_id"]; ok {
		t.Errorf("ordinary recipe carries candidate_of_scan_id = %s", v)
	}
}
