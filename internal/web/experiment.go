package web

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
)

// ErrInvalidExperiment is returned when an enqueue names an experiment it
// cannot run with.
var ErrInvalidExperiment = errors.New("invalid scan experiment")

const findingsOutputKind = "findings"

// validateExperimentEnqueue keeps experiments to repository-scoped findings
// scans of remote repositories, where the candidate can be pinned to the
// commit its baseline ran on, and keeps a candidate out of every scan group and
// triage cohort, so none of its output can reach a sibling. The configuration
// snapshot is checked here so a bad entry fails the form instead of the
// candidate.
func (s *Server) validateExperimentEnqueue(repo db.Repository, opts ScanOpts, sk db.Skill) error {
	if opts.Experiment == "" && opts.CandidateOfScanID == nil {
		return nil
	}
	if opts.Experiment == "" {
		return fmt.Errorf("%w: a candidate scan needs its experiment name", ErrInvalidExperiment)
	}
	if repo.IsLocal() {
		return fmt.Errorf("%w: a local directory has no commit a candidate can be pinned to", ErrInvalidExperiment)
	}
	if sk.OutputKind != findingsOutputKind {
		return fmt.Errorf("%w: skill %q does not report findings", ErrInvalidExperiment, sk.Name)
	}
	if opts.FindingID != nil || opts.DependentID != nil || opts.BaselineScanID != nil || opts.ExplorationMode != "" {
		return fmt.Errorf("%w: experiments only run on repository-scoped findings scans", ErrInvalidExperiment)
	}
	exp, err := parseExperimentConfig(opts.ExperimentConfig)
	if err != nil {
		return err
	}
	if opts.CandidateOfScanID == nil {
		return s.checkExperimentConfig(exp)
	}
	if opts.ScanGroup != "" || opts.TriageScanID != nil || opts.FocusArea != "" {
		return fmt.Errorf("%w: a candidate scan joins no scan group or triage cohort", ErrInvalidExperiment)
	}
	// enqueueSkillWith would replace an unknown model with the skill's default,
	// which would run a configuration nobody chose under the experiment's name.
	if !ValidModelPreference(opts.Model) {
		return fmt.Errorf("%w: candidate model %q is not configured", ErrInvalidExperiment, opts.Model)
	}
	return nil
}

// launchExperimentConfig snapshots the named scan_experiments entry for an
// ordinary scan launched with it. The candidate runs this snapshot, so editing
// or removing the entry later does not change what the operator picked.
func (s *Server) launchExperimentConfig(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	exp, ok := s.ScanExperiments[name]
	if !ok {
		return "", fmt.Errorf("%w: %q is not configured", ErrInvalidExperiment, name)
	}
	b, err := json.Marshal(exp)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidExperiment, err)
	}
	return string(b), nil
}

func parseExperimentConfig(raw string) (config.ScanExperiment, error) {
	var exp config.ScanExperiment
	if err := json.Unmarshal([]byte(raw), &exp); err != nil {
		return exp, fmt.Errorf("%w: unreadable configuration snapshot: %w", ErrInvalidExperiment, err)
	}
	return exp, nil
}

// checkExperimentConfig reports why an experiment snapshot cannot run on this
// instance: its model or skill no longer resolves.
func (s *Server) checkExperimentConfig(exp config.ScanExperiment) error {
	if exp.Model != "" && !ValidModelPreference(exp.Model) {
		return fmt.Errorf("%w: model %q is not configured", ErrInvalidExperiment, exp.Model)
	}
	_, err := s.experimentSkill(exp, 0)
	return err
}

// experimentSkill resolves the skill a candidate runs: the experiment's own
// when it names one, which must be an active findings skill, else fallback.
func (s *Server) experimentSkill(exp config.ScanExperiment, fallback uint) (uint, error) {
	if exp.Skill == "" {
		return fallback, nil
	}
	var sk db.Skill
	if err := s.DB.Select("id, active, output_kind").Where("name = ?", exp.Skill).First(&sk).Error; err != nil {
		return 0, fmt.Errorf("%w: skill %q: %w", ErrInvalidExperiment, exp.Skill, err)
	}
	if !sk.Active || sk.OutputKind != findingsOutputKind {
		return 0, fmt.Errorf("%w: skill %q is not an active findings skill", ErrInvalidExperiment, exp.Skill)
	}
	return sk.ID, nil
}

// enqueueCandidate starts the candidate run of a finalized ordinary scan that
// asked for an experiment. The candidate is pinned to the commit the baseline
// resolved and copies its scope, so only the experiment's settings differ. A
// candidate that cannot start is recorded as a failed candidate run with the
// reason, so the comparison counts it instead of hiding it in the server log.
func (s *Server) enqueueCandidate(scan *db.Scan) {
	if scan.Experiment == "" || scan.IsCandidate() || scan.SkillID == nil {
		return
	}
	log := s.Log.With("scan", scan.ID, "experiment", scan.Experiment)
	var existing int64
	if err := s.DB.Model(&db.Scan{}).Where("candidate_of_scan_id = ?", scan.ID).Count(&existing).Error; err != nil {
		log.Error("candidate not started: look up existing candidate", "err", err)
		return
	}
	if existing > 0 {
		return
	}
	if err := s.startCandidate(scan); err != nil {
		log.Warn("candidate not started", "err", err)
		s.recordRefusedCandidate(scan, err)
	}
}

func (s *Server) startCandidate(scan *db.Scan) error {
	exp, err := parseExperimentConfig(scan.ExperimentConfig)
	if err != nil {
		return err
	}
	if err := s.checkExperimentConfig(exp); err != nil {
		return err
	}
	skillID, err := s.experimentSkill(exp, *scan.SkillID)
	if err != nil {
		return err
	}
	_, err = s.enqueueSkillWith(context.Background(), scan.RepositoryID, skillID, ScanOpts{
		AuditSource:       db.SourceSystem,
		Model:             cmp.Or(exp.Model, scan.Model),
		Effort:            cmp.Or(exp.Effort, scan.Effort),
		Ref:               cmp.Or(scan.Commit, scan.Ref),
		SubPath:           scan.SubPath,
		ScopeMode:         scan.ScopeMode,
		Profile:           scan.Profile,
		EgressPolicy:      scan.EgressPolicy,
		MaxCostUSD:        scan.MaxCostUSD,
		RescanMode:        scan.RescanMode,
		DiffBaseScanID:    scan.DiffBaseScanID,
		Experiment:        scan.Experiment,
		ExperimentConfig:  scan.ExperimentConfig,
		CandidateOfScanID: &scan.ID,
	})
	return err
}

// recordRefusedCandidate stores a candidate that never ran as a failed
// candidate scan carrying the refusal. It holds no API token and is never
// queued.
func (s *Server) recordRefusedCandidate(scan *db.Scan, reason error) {
	now := time.Now()
	exp, _ := parseExperimentConfig(scan.ExperimentConfig)
	skillID, skillName := scan.SkillID, scan.SkillName
	if id, err := s.experimentSkill(exp, 0); err == nil && id != 0 {
		skillID, skillName = &id, exp.Skill
	}
	row := db.Scan{
		RepositoryID:      scan.RepositoryID,
		Kind:              scan.Kind,
		Status:            db.ScanFailed,
		StatusPriority:    db.StatusPriorityFor(db.ScanFailed),
		Model:             cmp.Or(exp.Model, scan.Model),
		Effort:            cmp.Or(exp.Effort, scan.Effort),
		SkillID:           skillID,
		SkillName:         skillName,
		Ref:               cmp.Or(scan.Commit, scan.Ref),
		SubPath:           scan.SubPath,
		ScopeMode:         scan.ScopeMode,
		Experiment:        scan.Experiment,
		ExperimentConfig:  scan.ExperimentConfig,
		CandidateOfScanID: &scan.ID,
		Error:             "candidate not started: " + reason.Error(),
		StartedAt:         &now,
		FinishedAt:        &now,
	}
	if err := s.DB.Create(&row).Error; err != nil {
		s.Log.Error("record refused candidate", "scan", scan.ID, "err", err)
	}
}

// retainedExperiment is the experiment, and its configuration snapshot, a
// retry carries. A candidate keeps its own, since its row records the
// configuration that ran. An ordinary scan keeps it only while the snapshot can
// still run, so removing the model or skill it names never blocks retrying the
// scan itself.
func (s *Server) retainedExperiment(scan db.Scan) (name, snapshot string) {
	if scan.Experiment == "" {
		return "", ""
	}
	if scan.IsCandidate() {
		return scan.Experiment, scan.ExperimentConfig
	}
	exp, err := parseExperimentConfig(scan.ExperimentConfig)
	if err != nil || s.checkExperimentConfig(exp) != nil {
		return "", ""
	}
	return scan.Experiment, scan.ExperimentConfig
}

// experimentRow pairs the baseline's and the candidate's observation of one
// fingerprint. Either side is nil when only the other reported it. FindingID
// is the canonical finding with that fingerprint, 0 when there is none.
type experimentRow struct {
	Baseline      *db.FindingObservation
	Candidate     *db.CandidateObservation
	FindingID     uint
	FindingStatus db.FindingLifecycle
}

// experimentSummary holds the comparison counts. Counts derived from operator
// assessments are only meaningful once Assessed is above zero, and the page
// shows them as unavailable before that.
type experimentSummary struct {
	Shared        int
	BaselineOnly  int
	CandidateOnly int
	Observations  int
	Assessed      int
	Unassessed    int
	// AdditionalConfirmed counts confirmed candidate-only observations that
	// match no repository finding: vulnerabilities neither the baseline nor any
	// earlier scan reported.
	AdditionalConfirmed int
	FalsePositives      int
	// KnownConfirmed counts confirmed candidate-only observations that match a
	// repository finding an earlier scan reported but the baseline missed.
	KnownConfirmed int
	// BaselineFalsePositives counts baseline observations whose repository
	// finding was rejected, out of BaselineTriaged whose finding an analyst
	// has moved past new or enriched.
	BaselineFalsePositives int
	BaselineTriaged        int
	BaselineObservations   int
	// EffortMinutes sums the analyst time recorded on EffortCount of the
	// candidate's observations.
	EffortMinutes int
	EffortCount   int
	FailedRuns    int
	// IncompleteRuns counts candidate runs that were cancelled or stopped by
	// their cost cap or turn limit before covering everything.
	IncompleteRuns int
}

// scanExperiment renders the comparison between an ordinary scan and the
// candidate runs of its experiment. A candidate's id redirects to its
// baseline's page with that run selected.
func (s *Server) scanExperiment(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if scan.IsCandidate() {
		http.Redirect(w, r, fmt.Sprintf("/scans/%d/experiment?candidate=%d", *scan.CandidateOfScanID, scan.ID), http.StatusSeeOther)
		return
	}
	if scan.Experiment == "" {
		http.NotFound(w, r)
		return
	}
	var repo db.Repository
	if err := s.DB.Select("id, name").First(&repo, scan.RepositoryID).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var runs []db.Scan
	if err := s.DB.Omit(scanBlobColumns...).Where("candidate_of_scan_id = ?", scan.ID).Order("id desc").Find(&runs).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		pageTitleKey: fmt.Sprintf("Experiment %s · scan #%d · %s", scan.Experiment, scan.ID, repo.Name),
		"Baseline":   scan,
		"Repo":       repo,
		"Runs":       runs,
	}
	selected := selectedCandidate(runs, r.URL.Query().Get("candidate"))
	if selected == nil {
		s.render(w, r, "scan_experiment.html", data)
		return
	}
	rows, summary, err := s.compareExperiment(scan, *selected)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, run := range runs {
		switch {
		case run.Status == db.ScanFailed:
			summary.FailedRuns++
		case run.Status == db.ScanCancelled, run.CostCapped, run.MaxTurnsHit:
			summary.IncompleteRuns++
		}
	}
	var decisions []db.ExperimentDecision
	if err := s.DB.Where("candidate_scan_id = ?", selected.ID).Order("id desc").Find(&decisions).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exp, err := parseExperimentConfig(selected.ExperimentConfig); err == nil {
		skillName := ""
		if scan.SkillID != nil {
			skillName = scan.SkillName
		}
		_, data["AdoptPlan"] = adoptionPlan(exp, skillName)
	}
	data["Candidate"] = selected
	data["Rows"] = rows
	data["Summary"] = summary
	data["Decisions"] = decisions
	data["Assessments"] = []string{db.CandidateConfirmed, db.CandidateFalsePositive, db.CandidateUnsure}
	s.render(w, r, "scan_experiment.html", data)
}

// selectedCandidate picks the run named by the candidate query value, or the
// latest run when the value names none of them.
func selectedCandidate(runs []db.Scan, raw string) *db.Scan {
	if len(runs) == 0 {
		return nil
	}
	if id, err := strconv.ParseUint(raw, 10, 0); err == nil {
		for i := range runs {
			if uint64(runs[i].ID) == id {
				return &runs[i]
			}
		}
	}
	return &runs[0]
}

// compareExperiment lines up the baseline's observations and one candidate
// run's by fingerprint: candidate-only rows first, then baseline-only, then
// the findings both reported.
func (s *Server) compareExperiment(baseline, candidate db.Scan) ([]experimentRow, experimentSummary, error) {
	var base []db.FindingObservation
	if err := s.DB.Where("scan_id = ?", baseline.ID).Order("id").Find(&base).Error; err != nil {
		return nil, experimentSummary{}, err
	}
	var cand []db.CandidateObservation
	if err := s.DB.Where("scan_id = ?", candidate.ID).Order("id").Find(&cand).Error; err != nil {
		return nil, experimentSummary{}, err
	}
	findings, err := s.canonicalByFingerprint(baseline.RepositoryID, base, cand)
	if err != nil {
		return nil, experimentSummary{}, err
	}

	baseByFP := make(map[string]*db.FindingObservation, len(base))
	for i := range base {
		baseByFP[base[i].Fingerprint] = &base[i]
	}
	var summary experimentSummary
	var candidateOnly, shared []experimentRow
	matched := map[string]bool{}
	for i := range cand {
		c := &cand[i]
		row := experimentRow{Candidate: c, Baseline: baseByFP[c.Fingerprint]}
		row.FindingID, row.FindingStatus = findings[c.Fingerprint].ID, findings[c.Fingerprint].Status
		summary.tally(c, row.Baseline == nil, row.FindingID != 0)
		if row.Baseline == nil {
			candidateOnly = append(candidateOnly, row)
			continue
		}
		matched[c.Fingerprint] = true
		shared = append(shared, row)
	}
	var baselineOnly []experimentRow
	for i := range base {
		b := &base[i]
		switch findings[b.Fingerprint].Status {
		case db.FindingNew, db.FindingEnriched, "":
		case db.FindingRejected:
			summary.BaselineTriaged++
			summary.BaselineFalsePositives++
		default:
			summary.BaselineTriaged++
		}
		if matched[b.Fingerprint] {
			continue
		}
		baselineOnly = append(baselineOnly, experimentRow{Baseline: b, FindingID: b.FindingID, FindingStatus: findings[b.Fingerprint].Status})
	}
	summary.Shared, summary.BaselineOnly, summary.CandidateOnly = len(shared), len(baselineOnly), len(candidateOnly)
	summary.Observations, summary.BaselineObservations = len(cand), len(base)
	return slices.Concat(candidateOnly, baselineOnly, shared), summary, nil
}

func (sum *experimentSummary) tally(c *db.CandidateObservation, candidateOnly, knownToRepository bool) {
	switch c.Assessment {
	case "":
		sum.Unassessed++
	case db.CandidateConfirmed:
		sum.Assessed++
		switch {
		case candidateOnly && knownToRepository:
			sum.KnownConfirmed++
		case candidateOnly:
			sum.AdditionalConfirmed++
		}
	case db.CandidateFalsePositive:
		sum.Assessed++
		sum.FalsePositives++
	default:
		sum.Assessed++
	}
	if c.EffortMinutes != nil {
		sum.EffortMinutes += *c.EffortMinutes
		sum.EffortCount++
	}
}

// canonicalByFingerprint maps each fingerprint either side reported to the
// repository's oldest finding with it, which is the row a rescan re-observes.
func (s *Server) canonicalByFingerprint(repoID uint, base []db.FindingObservation, cand []db.CandidateObservation) (map[string]db.Finding, error) {
	fps := make([]string, 0, len(base)+len(cand))
	for _, b := range base {
		fps = append(fps, b.Fingerprint)
	}
	for _, c := range cand {
		fps = append(fps, c.Fingerprint)
	}
	out := map[string]db.Finding{}
	if len(fps) == 0 {
		return out, nil
	}
	var rows []db.Finding
	if err := s.DB.Select("id, fingerprint, status").Where("repository_id = ? AND fingerprint IN ?", repoID, fps).
		Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, f := range rows {
		if _, seen := out[f.Fingerprint]; !seen {
			out[f.Fingerprint] = f
		}
	}
	return out, nil
}

// candidateObservationAssess records the operator's verdict on one candidate
// observation. It writes only the observation row: a confirmed candidate
// finding does not become a repository finding.
func (s *Server) candidateObservationAssess(w http.ResponseWriter, r *http.Request) {
	obs, ok := loadByID[db.CandidateObservation](s, w, r)
	if !ok {
		return
	}
	assessment := r.FormValue("assessment")
	if assessment != "" && !slices.Contains([]string{db.CandidateConfirmed, db.CandidateFalsePositive, db.CandidateUnsure}, assessment) {
		http.Error(w, fmt.Sprintf("unknown assessment %q", assessment), http.StatusUnprocessableEntity)
		return
	}
	effort, err := parseEffortMinutes(r.FormValue("effort_minutes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	var assessedAt *time.Time
	if assessment != "" {
		now := time.Now()
		assessedAt = &now
	}
	if err := s.DB.Model(&db.CandidateObservation{}).Where("id = ?", obs.ID).Updates(map[string]any{
		"assessment":      assessment,
		"assessment_note": strings.TrimSpace(r.FormValue("note")),
		"effort_minutes":  effort,
		"assessed_at":     assessedAt,
	}).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d/experiment", obs.ScanID))
}

// parseEffortMinutes reads the optional analyst time field. Empty means not
// recorded.
func parseEffortMinutes(raw string) (*int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("effort_minutes %q is not a whole number of minutes", raw)
	}
	return &n, nil
}

// scanExperimentDecision records whether the operator adopts or rejects the
// configuration a candidate scan ran with. Adopting is the explicit step that
// applies it to ordinary scans, as far as a per-skill setting can carry it: an
// experiment that only changed the model sets that model on the ordinary
// scan's skill. A changed effort is a global setting and a changed skill is a
// different skill, so both stay manual and the decision says so.
func (s *Server) scanExperimentDecision(w http.ResponseWriter, r *http.Request) {
	scan, ok := loadByID[db.Scan](s, w, r)
	if !ok {
		return
	}
	if !scan.IsCandidate() {
		http.Error(w, "decisions are recorded on a candidate scan", http.StatusBadRequest)
		return
	}
	decision := r.FormValue("decision")
	if decision != db.ExperimentAdopt && decision != db.ExperimentReject {
		http.Error(w, fmt.Sprintf("unknown decision %q", decision), http.StatusUnprocessableEntity)
		return
	}
	exp, err := parseExperimentConfig(scan.ExperimentConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	row := db.ExperimentDecision{
		RepositoryID:    scan.RepositoryID,
		CandidateScanID: scan.ID,
		Experiment:      scan.Experiment,
		Decision:        decision,
		Note:            strings.TrimSpace(r.FormValue("note")),
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if decision == db.ExperimentAdopt {
			applied, err := adoptExperiment(tx, scan, exp)
			if err != nil {
				return err
			}
			row.Applied = applied
		}
		return tx.Create(&row).Error
	}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/scans/%d/experiment", scan.ID))
}

// adoptionPlan says what adopting exp applies to the ordinary scan's skill and
// what it leaves to the operator. Only a changed model maps to a per-skill
// setting, and only when the candidate ran the same skill.
func adoptionPlan(exp config.ScanExperiment, skillName string) (applyModel bool, summary string) {
	var manual []string
	if exp.Effort != "" {
		manual = append(manual, fmt.Sprintf("effort %s is a global setting", exp.Effort))
	}
	if exp.Skill != "" {
		manual = append(manual, fmt.Sprintf("skill %s replaces the ordinary skill", exp.Skill))
	}
	applyModel = exp.Model != "" && exp.Skill == "" && skillName != ""
	var parts []string
	if applyModel {
		parts = append(parts, fmt.Sprintf("sets %s model to %s", skillName, exp.Model))
	}
	if len(manual) > 0 {
		parts = append(parts, "leaves to you: "+strings.Join(manual, ", "))
	}
	if len(parts) == 0 {
		return false, "applies nothing"
	}
	return applyModel, strings.Join(parts, ". ")
}

// adoptExperiment applies the adoption plan and returns its description.
func adoptExperiment(tx *gorm.DB, candidate db.Scan, exp config.ScanExperiment) (string, error) {
	var baseline db.Scan
	if err := tx.Select("id", "skill_id", "skill_name").First(&baseline, *candidate.CandidateOfScanID).Error; err != nil {
		return "", fmt.Errorf("load baseline scan: %w", err)
	}
	skillName := ""
	if baseline.SkillID != nil {
		skillName = baseline.SkillName
	}
	applyModel, summary := adoptionPlan(exp, skillName)
	if !applyModel {
		return summary, nil
	}
	if !ValidModelPreference(exp.Model) {
		return "", fmt.Errorf("%w: model %q is not configured", ErrInvalidExperiment, exp.Model)
	}
	if err := tx.Model(&db.Skill{}).Where("id = ?", *baseline.SkillID).Update("model", exp.Model).Error; err != nil {
		return "", err
	}
	return summary, nil
}
