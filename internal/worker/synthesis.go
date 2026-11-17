package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"scrutineer/internal/db"
)

const (
	synthesizeSkillName = "synthesize"
	minSynthesisSources = 2
	maxSynthesisReports = 32
	maxSynthesisClaims  = 64
	maxSynthesisText    = 2000
)

var synthesisDisagreementFields = []string{"severity", "reachability", "security_impact"}

// synthesisInput is the host-authored snapshot staged at import/report. It
// names no skill, backend, model or scan, so the synthesizer sees each
// observation under its neutral label only.
type synthesisInput struct {
	FindingID uint              `json:"finding_id"`
	Reports   []synthesisReport `json:"reports"`
}

type synthesisReport struct {
	Label         string          `json:"label"`
	ObservationID uint            `json:"observation_id"`
	Commit        string          `json:"commit,omitempty"`
	Title         string          `json:"title,omitempty"`
	Severity      string          `json:"severity,omitempty"`
	Confidence    string          `json:"confidence,omitempty"`
	CWE           string          `json:"cwe,omitempty"`
	Location      string          `json:"location,omitempty"`
	Reachability  string          `json:"reachability,omitempty"`
	Rating        string          `json:"rating,omitempty"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
}

type synthesisOutput struct {
	Summary       string                  `json:"summary"`
	Claims        []synthesisClaim        `json:"claims"`
	Disagreements []synthesisDisagreement `json:"disagreements"`
	Unused        []synthesisUnused       `json:"unused"`
}

type synthesisClaim struct {
	Statement string   `json:"statement"`
	Sources   []string `json:"sources"`
}

type synthesisDisagreement struct {
	Field     string              `json:"field"`
	Positions []synthesisPosition `json:"positions"`
}

type synthesisPosition struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

type synthesisUnused struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// prepareSynthesis freezes the finding's observations into ImportPayload
// before any model turn. A retry carries the snapshot over and replays it.
func (w *Worker) prepareSynthesis(scan *db.Scan) error {
	if scan.FindingID == nil {
		return errors.New("synthesize requires a finding")
	}
	if len(scan.ImportPayload) != 0 {
		input, err := decodeSynthesisInput(scan)
		if err != nil {
			return err
		}
		return validateSynthesisInput(input)
	}
	rows, _, err := db.FindingContributions(w.DB, *scan.FindingID, 0)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}
	if len(rows) < minSynthesisSources {
		return errors.New("synthesize needs at least two observations of this finding")
	}
	if len(rows) > maxSynthesisReports {
		return fmt.Errorf("finding has more than %d observations to synthesize", maxSynthesisReports)
	}
	input := synthesisInput{FindingID: *scan.FindingID}
	for i, o := range rows {
		if o.RepositoryID != scan.RepositoryID {
			return fmt.Errorf("observation %d belongs to another repository", o.ID)
		}
		input.Reports = append(input.Reports, synthesisReport{
			Label: fmt.Sprintf("R%d", i+1), ObservationID: o.ID, Commit: o.Commit, Title: o.Title,
			Severity: o.Severity, Confidence: o.Confidence, CWE: o.CWE, Location: o.Location,
			Reachability: o.Reachability, Rating: o.Rating, Evidence: rawEvidence(o.Evidence),
		})
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("import_payload", raw).Error; err != nil {
		return err
	}
	scan.ImportPayload = raw
	return nil
}

func rawEvidence(s string) json.RawMessage {
	if !json.Valid([]byte(s)) {
		return nil
	}
	return json.RawMessage(s)
}

func decodeSynthesisInput(scan *db.Scan) (synthesisInput, error) {
	var input synthesisInput
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		return input, fmt.Errorf("read synthesis snapshot: %w", err)
	}
	if scan.FindingID == nil || input.FindingID != *scan.FindingID {
		return input, errors.New("synthesis snapshot belongs to another finding")
	}
	return input, nil
}

func validateSynthesisInput(input synthesisInput) error {
	if len(input.Reports) < minSynthesisSources || len(input.Reports) > maxSynthesisReports {
		return fmt.Errorf("synthesis snapshot must hold 2 to %d reports", maxSynthesisReports)
	}
	seen := map[string]bool{}
	for _, r := range input.Reports {
		if r.Label == "" || r.ObservationID == 0 || seen[r.Label] {
			return errors.New("synthesis snapshot has a missing or repeated label")
		}
		seen[r.Label] = true
	}
	return nil
}

// validateSynthesis rejects the whole report on any citation the snapshot
// does not hold, and requires every input report to be cited or listed as
// unused so no reviewer drops out silently.
func validateSynthesis(input synthesisInput, out synthesisOutput) error {
	c := synthesisCitations{reports: map[string]synthesisReport{}, covered: map[string]bool{}}
	for _, r := range input.Reports {
		c.reports[r.Label] = r
	}
	if err := checkSynthesisText("summary", out.Summary); err != nil {
		return err
	}
	if err := c.claims(out.Claims); err != nil {
		return err
	}
	if err := c.disagreements(out.Disagreements); err != nil {
		return err
	}
	for _, u := range out.Unused {
		if c.covered[u.Source] {
			return fmt.Errorf("unused source %q is already cited or listed", u.Source)
		}
		if err := checkSynthesisText("unused reason", u.Reason); err != nil {
			return err
		}
		if err := c.cite(u.Source); err != nil {
			return err
		}
	}
	for _, r := range input.Reports {
		if !c.covered[r.Label] {
			return fmt.Errorf("synthesis omits source %q", r.Label)
		}
	}
	return nil
}

type synthesisCitations struct {
	reports map[string]synthesisReport
	covered map[string]bool
}

func (c synthesisCitations) cite(label string) error {
	if _, ok := c.reports[label]; !ok {
		return fmt.Errorf("synthesis cites unknown source %q", label)
	}
	c.covered[label] = true
	return nil
}

func (c synthesisCitations) claims(claims []synthesisClaim) error {
	if len(claims) == 0 || len(claims) > maxSynthesisClaims {
		return fmt.Errorf("synthesis must hold 1 to %d claims", maxSynthesisClaims)
	}
	for _, claim := range claims {
		if err := checkSynthesisText("claim", claim.Statement); err != nil {
			return err
		}
		if len(claim.Sources) == 0 {
			return errors.New("synthesis claim cites no source")
		}
		for i, src := range claim.Sources {
			if slices.Contains(claim.Sources[:i], src) {
				return fmt.Errorf("synthesis claim cites %q twice", src)
			}
			if err := c.cite(src); err != nil {
				return err
			}
		}
	}
	return nil
}

// disagreements checks each position on a structured field against the value
// its report recorded, and requires an entry for every structured field on
// which the snapshot's reports differ.
func (c synthesisCitations) disagreements(ds []synthesisDisagreement) error {
	listed := map[string]bool{}
	for _, d := range ds {
		if !slices.Contains(synthesisDisagreementFields, d.Field) {
			return fmt.Errorf("unknown disagreement field %q", d.Field)
		}
		if listed[d.Field] {
			return fmt.Errorf("%s disagreement is listed twice", d.Field)
		}
		listed[d.Field] = true
		if len(d.Positions) < minSynthesisSources {
			return fmt.Errorf("%s disagreement needs at least two positions", d.Field)
		}
		for i, p := range d.Positions {
			if err := c.position(d.Field, d.Positions[:i], p); err != nil {
				return err
			}
		}
	}
	for _, field := range synthesisDisagreementFields {
		if !listed[field] && c.differ(field) {
			return fmt.Errorf("synthesis omits the %s disagreement", field)
		}
	}
	return nil
}

func (c synthesisCitations) position(field string, earlier []synthesisPosition, p synthesisPosition) error {
	if slices.ContainsFunc(earlier, func(prev synthesisPosition) bool { return prev.Source == p.Source }) {
		return fmt.Errorf("%s disagreement lists %q twice", field, p.Source)
	}
	if err := checkSynthesisText("position", p.Value); err != nil {
		return err
	}
	if err := c.cite(p.Source); err != nil {
		return err
	}
	if want, ok := reportedValue(c.reports[p.Source], field); ok && !strings.EqualFold(strings.TrimSpace(p.Value), want) {
		return fmt.Errorf("%s position for %q does not match its report", field, p.Source)
	}
	return nil
}

func (c synthesisCitations) differ(field string) bool {
	first := ""
	for _, r := range c.reports {
		v, ok := reportedValue(r, field)
		if !ok || v == "" {
			continue
		}
		if first == "" {
			first = v
		} else if !strings.EqualFold(v, first) {
			return true
		}
	}
	return false
}

// reportedValue returns what a report recorded for a structured field.
// security_impact is prose and has no recorded value to compare against.
func reportedValue(r synthesisReport, field string) (string, bool) {
	switch field {
	case "severity":
		return strings.TrimSpace(r.Severity), true
	case "reachability":
		return strings.TrimSpace(r.Reachability), true
	}
	return "", false
}

func checkSynthesisText(name, s string) error {
	if strings.TrimSpace(s) == "" || len(s) > maxSynthesisText {
		return fmt.Errorf("synthesis %s must be 1 to %d bytes", name, maxSynthesisText)
	}
	return nil
}

func (w *Worker) parseSynthesisOutput(scan *db.Scan, report string) error {
	input, err := decodeSynthesisInput(scan)
	if err != nil {
		return err
	}
	if err := validateSynthesisInput(input); err != nil {
		return err
	}
	var out synthesisOutput
	decoder := json.NewDecoder(strings.NewReader(report))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return fmt.Errorf("parse synthesis: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("synthesis report must contain exactly one JSON object")
	}
	if err := validateSynthesis(input, out); err != nil {
		return err
	}
	// The snapshot is host-authored, but re-check its sources against the
	// finding and repository as they stand now before persisting anything.
	findingIDs, err := db.ContributionFindingIDs(w.DB, *scan.FindingID)
	if err != nil {
		return fmt.Errorf("load contributions: %w", err)
	}
	ids := make([]uint, 0, len(input.Reports))
	for _, r := range input.Reports {
		ids = append(ids, r.ObservationID)
	}
	var rows []db.FindingObservation
	if err := w.DB.Select("id", "finding_id", "repository_id").Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return fmt.Errorf("load synthesis sources: %w", err)
	}
	sources := make(map[string]uint, len(input.Reports))
	for _, r := range input.Reports {
		i := slices.IndexFunc(rows, func(o db.FindingObservation) bool { return o.ID == r.ObservationID })
		if i < 0 {
			return fmt.Errorf("synthesis source %s no longer exists", r.Label)
		}
		if rows[i].RepositoryID != scan.RepositoryID || !slices.Contains(findingIDs, rows[i].FindingID) {
			return fmt.Errorf("synthesis source %s is outside this finding", r.Label)
		}
		sources[r.Label] = r.ObservationID
	}
	rawReport, err := json.Marshal(out)
	if err != nil {
		return err
	}
	rawSources, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	return db.RecordFindingSynthesis(w.DB, &db.FindingSynthesis{
		FindingID: *scan.FindingID, ScanID: scan.ID, RepositoryID: scan.RepositoryID,
		Report: string(rawReport), Sources: string(rawSources),
	})
}
