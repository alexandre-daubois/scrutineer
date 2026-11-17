package web

import (
	"encoding/json"
	"errors"
	"net/http"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const synthesizeSkillName = "synthesize"

// synthesisSourceView is one neutral label with the observation behind it,
// attached only when the synthesis is displayed.
type synthesisSourceView struct {
	Label       string
	Observation *db.FindingObservation
}

type synthesisClaimView struct {
	Statement string
	Sources   []synthesisSourceView
}

type synthesisPositionView struct {
	Source synthesisSourceView
	Value  string
}

type synthesisDisagreementView struct {
	Field     string
	Positions []synthesisPositionView
}

type synthesisUnusedView struct {
	Source synthesisSourceView
	Reason string
}

type findingSynthesisView struct {
	ScanID        uint
	Summary       string
	Claims        []synthesisClaimView
	Disagreements []synthesisDisagreementView
	Unused        []synthesisUnusedView
}

// loadFindingSynthesisView returns the finding's newest synthesis with each
// label resolved to its observation, or nil when there is none.
func loadFindingSynthesisView(gdb *gorm.DB, findingID uint) (*findingSynthesisView, error) {
	var row db.FindingSynthesis
	if err := gdb.Where("finding_id = ?", findingID).Order("id DESC").First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var report struct {
		Summary string `json:"summary"`
		Claims  []struct {
			Statement string   `json:"statement"`
			Sources   []string `json:"sources"`
		} `json:"claims"`
		Disagreements []struct {
			Field     string `json:"field"`
			Positions []struct {
				Source string `json:"source"`
				Value  string `json:"value"`
			} `json:"positions"`
		} `json:"disagreements"`
		Unused []struct {
			Source string `json:"source"`
			Reason string `json:"reason"`
		} `json:"unused"`
	}
	if err := json.Unmarshal([]byte(row.Report), &report); err != nil {
		return nil, err
	}
	var labels map[string]uint
	if err := json.Unmarshal([]byte(row.Sources), &labels); err != nil {
		return nil, err
	}
	ids := make([]uint, 0, len(labels))
	for _, id := range labels {
		ids = append(ids, id)
	}
	var rows []db.FindingObservation
	if err := gdb.Where("id IN ? AND repository_id = ?", ids, row.RepositoryID).Find(&rows).Error; err != nil {
		return nil, err
	}
	byID := map[uint]*db.FindingObservation{}
	for i := range rows {
		byID[rows[i].ID] = &rows[i]
	}
	source := func(label string) synthesisSourceView {
		return synthesisSourceView{Label: label, Observation: byID[labels[label]]}
	}
	v := &findingSynthesisView{ScanID: row.ScanID, Summary: report.Summary}
	for _, c := range report.Claims {
		cv := synthesisClaimView{Statement: c.Statement}
		for _, l := range c.Sources {
			cv.Sources = append(cv.Sources, source(l))
		}
		v.Claims = append(v.Claims, cv)
	}
	for _, d := range report.Disagreements {
		dv := synthesisDisagreementView{Field: d.Field}
		for _, p := range d.Positions {
			dv.Positions = append(dv.Positions, synthesisPositionView{Source: source(p.Source), Value: p.Value})
		}
		v.Disagreements = append(v.Disagreements, dv)
	}
	for _, u := range report.Unused {
		v.Unused = append(v.Unused, synthesisUnusedView{Source: source(u.Source), Reason: u.Reason})
	}
	return v, nil
}

func (s *Server) findingSynthesis(findingID uint) *findingSynthesisView {
	v, err := loadFindingSynthesisView(s.DB, findingID)
	if err != nil {
		s.Log.Warn("load finding synthesis", "finding", findingID, "err", err)
	}
	return v
}

func (s *Server) findingSynthesize(w http.ResponseWriter, r *http.Request) {
	s.runFindingSkill(w, r, synthesizeSkillName, true)
}
