package web

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	"scrutineer/internal/db"
)

const (
	usageOutlierMultiple              = 10
	usageCorrelationMinSamples        = 3
	usageCorrelationStrongThreshold   = 0.7
	usageCorrelationModerateThreshold = 0.4
)

const (
	usageDriverSLOC      = "SLOC"
	usageDriverManifests = "Dependency manifests"
	usageDriverSinks     = "Phase 1 sinks"
)

type usageDriverAnalysis struct {
	Correlations []usageDriverCorrelation
	Outliers     []usageCostOutlier
}

type usageDriverCorrelation struct {
	Skill   string
	Driver  string
	Samples int
	R       float64
	Summary string
}

type usageCostOutlier struct {
	ScanID       uint
	RepositoryID uint
	Repository   string
	Skill        string
	Model        string
	Profile      string
	Cost         float64
	Median       float64
	Multiple     float64
	Turns        int
	SLOC         string
	Manifests    string
	Sinks        string
}

type usageDriverValues struct {
	SLOC      *int
	Manifests *int
	Sinks     *int
}

type usageDriverPair struct {
	Driver float64
	Cost   float64
}

func (s *Server) loadUsageDriverAnalysis(scans []db.Scan) usageDriverAnalysis {
	values := usageDriverValuesByScan(
		scans,
		s.loadUsageSLOC(),
		s.loadUsageManifestCounts(),
		s.loadUsageDeepDiveSinks(),
	)
	analysis := usageDriverAnalysis{
		Correlations: usageCorrelations(scans, values),
		Outliers:     usageOutliers(scans, values),
	}
	s.loadUsageOutlierRepositoryNames(analysis.Outliers)
	return analysis
}

func (s *Server) loadUsageSLOC() map[uint]int {
	latest := s.DB.Model(&db.Scan{}).
		Select("MAX(id)").
		Where("status = ? AND skill_name = ? AND report != ''", db.ScanDone, "repo-overview").
		Group("repository_id")
	var sources []db.Scan
	s.DB.Select("id", "repository_id", "report").Where("id IN (?)", latest).Find(&sources)

	values := make(map[uint]int, len(sources))
	for _, source := range sources {
		if sloc, ok := repoOverviewSLOC(source.Report); ok {
			values[source.RepositoryID] = sloc
		}
	}
	return values
}

func (s *Server) loadUsageManifestCounts() map[uint]int {
	var rows []struct {
		RepositoryID  uint
		ManifestCount int
	}
	s.DB.Model(&db.Dependency{}).
		Select("repository_id, COUNT(DISTINCT TRIM(manifest_path)) AS manifest_count").
		Where("TRIM(manifest_path) != ''").
		Group("repository_id").
		Scan(&rows)

	values := make(map[uint]int, len(rows))
	for _, row := range rows {
		values[row.RepositoryID] = row.ManifestCount
	}
	return values
}

func (s *Server) loadUsageDeepDiveSinks() map[uint]int {
	latest := s.DB.Model(&db.Scan{}).
		Select("MAX(id)").
		Where("status = ? AND skill_name = ? AND cost_usd > 0 AND report != '' AND candidate_of_scan_id IS NULL", db.ScanDone, "security-deep-dive").
		Group("repository_id")
	var sources []db.Scan
	s.DB.Select("id", "report").Where("id IN (?)", latest).Find(&sources)

	values := make(map[uint]int, len(sources))
	for _, source := range sources {
		if sinks, ok := deepDiveSinkCount(source.Report); ok {
			values[source.ID] = sinks
		}
	}
	return values
}

func usageDriverValuesByScan(scans []db.Scan, slocByRepo, manifestsByRepo map[uint]int, sinksByScan map[uint]int) map[uint]usageDriverValues {
	values := make(map[uint]usageDriverValues, len(scans))
	for _, scan := range scans {
		v := usageDriverValues{}
		if sinks, ok := sinksByScan[scan.ID]; ok {
			v.Sinks = new(sinks)
		}
		// repo-overview and dependencies describe the repository root. Applying
		// those values to narrower scans would overstate their actual scope.
		if scan.SubPath == "" && scan.FocusArea == "" {
			if sloc, ok := slocByRepo[scan.RepositoryID]; ok && scan.SkillName != "repo-overview" {
				v.SLOC = new(sloc)
			}
			if manifests, ok := manifestsByRepo[scan.RepositoryID]; ok && scan.SkillName != "dependencies" {
				v.Manifests = new(manifests)
			}
		}
		values[scan.ID] = v
	}
	return values
}

func repoOverviewSLOC(report string) (int, bool) {
	var result struct {
		Lines struct {
			TotalLines *int `json:"total_lines"`
		} `json:"lines"`
	}
	if json.Unmarshal([]byte(report), &result) != nil || result.Lines.TotalLines == nil || *result.Lines.TotalLines < 0 {
		return 0, false
	}
	return *result.Lines.TotalLines, true
}

func deepDiveSinkCount(report string) (int, bool) {
	var result struct {
		Inventory []json.RawMessage `json:"inventory"`
	}
	if json.Unmarshal([]byte(report), &result) != nil || result.Inventory == nil {
		return 0, false
	}
	return len(result.Inventory), true
}

func usageCorrelations(scans []db.Scan, values map[uint]usageDriverValues) []usageDriverCorrelation {
	pairs := map[string]map[string][]usageDriverPair{}
	for _, scan := range scans {
		if scan.CostUSD <= 0 {
			continue
		}
		v := values[scan.ID]
		appendUsagePair(pairs, scan.SkillName, usageDriverSLOC, v.SLOC, scan.CostUSD)
		appendUsagePair(pairs, scan.SkillName, usageDriverManifests, v.Manifests, scan.CostUSD)
		appendUsagePair(pairs, scan.SkillName, usageDriverSinks, v.Sinks, scan.CostUSD)
	}

	var rows []usageDriverCorrelation
	for skill, byDriver := range pairs {
		for driver, observations := range byDriver {
			r, ok := pearsonCorrelation(observations)
			if !ok {
				continue
			}
			rows = append(rows, usageDriverCorrelation{
				Skill:   skill,
				Driver:  driver,
				Samples: len(observations),
				R:       r,
				Summary: correlationSummary(r),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := math.Abs(rows[i].R), math.Abs(rows[j].R)
		if left != right {
			return left > right
		}
		if rows[i].Skill != rows[j].Skill {
			return rows[i].Skill < rows[j].Skill
		}
		return rows[i].Driver < rows[j].Driver
	})
	return rows
}

func appendUsagePair(pairs map[string]map[string][]usageDriverPair, skill, driver string, value *int, cost float64) {
	if value == nil {
		return
	}
	if pairs[skill] == nil {
		pairs[skill] = map[string][]usageDriverPair{}
	}
	pairs[skill][driver] = append(pairs[skill][driver], usageDriverPair{Driver: float64(*value), Cost: cost})
}

func pearsonCorrelation(pairs []usageDriverPair) (float64, bool) {
	if len(pairs) < usageCorrelationMinSamples {
		return 0, false
	}
	var driverMean, costMean float64
	for _, pair := range pairs {
		driverMean += pair.Driver
		costMean += pair.Cost
	}
	driverMean /= float64(len(pairs))
	costMean /= float64(len(pairs))

	var covariance, driverVariance, costVariance float64
	for _, pair := range pairs {
		driverDelta := pair.Driver - driverMean
		costDelta := pair.Cost - costMean
		covariance += driverDelta * costDelta
		driverVariance += driverDelta * driverDelta
		costVariance += costDelta * costDelta
	}
	if driverVariance == 0 || costVariance == 0 {
		return 0, false
	}
	return covariance / math.Sqrt(driverVariance*costVariance), true
}

func correlationSummary(r float64) string {
	strength := "weak"
	abs := math.Abs(r)
	if abs >= usageCorrelationStrongThreshold {
		strength = "strong"
	} else if abs >= usageCorrelationModerateThreshold {
		strength = "moderate"
	}
	direction := "positive"
	if r < 0 {
		direction = "negative"
	}
	return strength + " " + direction
}

func usageOutliers(scans []db.Scan, values map[uint]usageDriverValues) []usageCostOutlier {
	costsBySkill := map[string][]float64{}
	for _, scan := range scans {
		if scan.CostUSD > 0 {
			costsBySkill[scan.SkillName] = append(costsBySkill[scan.SkillName], scan.CostUSD)
		}
	}
	medians := map[string]float64{}
	for skill, costs := range costsBySkill {
		medians[skill] = summarise(costs).Median
	}

	var rows []usageCostOutlier
	for _, scan := range scans {
		median := medians[scan.SkillName]
		if median <= 0 || scan.CostUSD < usageOutlierMultiple*median {
			continue
		}
		v := values[scan.ID]
		rows = append(rows, usageCostOutlier{
			ScanID:       scan.ID,
			RepositoryID: scan.RepositoryID,
			Skill:        scan.SkillName,
			Model:        scan.Model,
			Profile:      scan.Profile,
			Cost:         scan.CostUSD,
			Median:       median,
			Multiple:     scan.CostUSD / median,
			Turns:        scan.Turns,
			SLOC:         usageDriverDisplay(v.SLOC),
			Manifests:    usageDriverDisplay(v.Manifests),
			Sinks:        usageDriverDisplay(v.Sinks),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Multiple != rows[j].Multiple {
			return rows[i].Multiple > rows[j].Multiple
		}
		return rows[i].Cost > rows[j].Cost
	})
	return rows
}

func (s *Server) loadUsageOutlierRepositoryNames(outliers []usageCostOutlier) {
	if len(outliers) == 0 {
		return
	}
	seen := make(map[uint]struct{}, len(outliers))
	ids := make([]uint, 0, len(outliers))
	for _, outlier := range outliers {
		if _, ok := seen[outlier.RepositoryID]; ok {
			continue
		}
		seen[outlier.RepositoryID] = struct{}{}
		ids = append(ids, outlier.RepositoryID)
	}
	var repos []db.Repository
	s.DB.Select("id", "name", "full_name").Where("id IN ?", ids).Find(&repos)
	names := make(map[uint]string, len(repos))
	for _, repo := range repos {
		names[repo.ID] = usageRepositoryName(repo)
	}
	for i := range outliers {
		if name := names[outliers[i].RepositoryID]; name != "" {
			outliers[i].Repository = name
		} else {
			outliers[i].Repository = fmt.Sprintf("repository #%d", outliers[i].RepositoryID)
		}
	}
}

func usageRepositoryName(repo db.Repository) string {
	if repo.FullName != "" {
		return repo.FullName
	}
	if repo.Name != "" {
		return repo.Name
	}
	return fmt.Sprintf("repository #%d", repo.ID)
}

func usageDriverDisplay(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}
