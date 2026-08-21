package report

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	LocalPostureSnapshotOrigin = "LOCAL_SCAN"
	localRegressionContract    = "local-regression.v1"
	localFindingIndexKey       = "_local_finding_index"
	localFindingIndexLimit     = 20000
	localFindingChangeLimit    = 100
)

type LocalFindingIndexItem struct {
	ID       string              `json:"id"`
	Type     string              `json:"type"`
	Severity model.Severity      `json:"severity"`
	Status   model.FindingStatus `json:"status"`
}

type localFindingIndex struct {
	Complete bool                    `json:"complete"`
	Count    int                     `json:"count"`
	Items    []LocalFindingIndexItem `json:"items,omitempty"`
}

type LocalFindingChange struct {
	ID       string              `json:"-"`
	Type     string              `json:"type"`
	Severity model.Severity      `json:"severity"`
	From     model.FindingStatus `json:"from,omitempty"`
	To       model.FindingStatus `json:"to,omitempty"`
	Change   string              `json:"change"`
}

type LocalFindingDiff struct {
	Comparable       bool                 `json:"comparable"`
	Reason           string               `json:"reason,omitempty"`
	PreviousCount    int                  `json:"previous_count"`
	CurrentCount     int                  `json:"current_count"`
	NewOpen          int                  `json:"new_open"`
	PersistentOpen   int                  `json:"persistent_open"`
	Triaged          int                  `json:"triaged"`
	Reopened         int                  `json:"reopened"`
	Cleared          int                  `json:"cleared"`
	Changes          []LocalFindingChange `json:"changes"`
	ChangesTruncated bool                 `json:"changes_truncated"`
}

type LocalRegressionReport struct {
	ContractVersion  string            `json:"contract_version"`
	State            string            `json:"state"`
	SnapshotCount    int               `json:"snapshot_count"`
	Previous         *TrendPoint       `json:"previous,omitempty"`
	Current          *TrendPoint       `json:"current,omitempty"`
	Delta            map[string]int    `json:"delta"`
	RegressedMetrics []string          `json:"regressed_metrics"`
	ImprovedMetrics  []string          `json:"improved_metrics"`
	FindingDiff      *LocalFindingDiff `json:"finding_diff,omitempty"`
}

func SaveLocalPostureSnapshot(ctx context.Context, store *storage.Store, execution model.ExecutionResult) (model.ReportExport, error) {
	if store == nil || store.ReportExports == nil {
		return model.ReportExport{}, errors.New("report export storage is unavailable")
	}
	executionID := strings.TrimSpace(execution.ID)
	if executionID == "" {
		return model.ReportExport{}, errors.New("execution ID is required")
	}
	export, err := BuildExport(ctx, store, "governance", "json")
	if err != nil {
		return model.ReportExport{}, err
	}
	findings, err := store.Findings.List(ctx, storage.FindingFilter{})
	if err != nil {
		return model.ReportExport{}, err
	}
	export.Content, err = addLocalFindingIndex(export.Content, findings)
	if err != nil {
		return model.ReportExport{}, err
	}
	export.ID = model.StableID("local_posture_snapshot", executionID)
	export.Origin = LocalPostureSnapshotOrigin
	export.ExecutionID = executionID
	if !execution.FinishedAt.IsZero() {
		export.CreatedAt = execution.FinishedAt.UTC()
	}
	if err := store.ReportExports.Save(ctx, export); err != nil {
		return model.ReportExport{}, err
	}
	return export, nil
}

func BuildLocalRegression(ctx context.Context, store *storage.Store) (LocalRegressionReport, error) {
	result := LocalRegressionReport{
		ContractVersion:  localRegressionContract,
		State:            "NO_BASELINE",
		Delta:            map[string]int{},
		RegressedMetrics: []string{},
		ImprovedMetrics:  []string{},
	}
	if store == nil || store.ReportExports == nil {
		return result, errors.New("report export storage is unavailable")
	}
	exports, err := store.ReportExports.List(ctx)
	if err != nil {
		return result, err
	}
	type localSnapshot struct {
		Point TrendPoint
		Index *localFindingIndex
	}
	points := make([]localSnapshot, 0, len(exports))
	for _, export := range exports {
		if export.Origin != LocalPostureSnapshotOrigin || export.Type != "governance" || export.Format != "json" {
			continue
		}
		point, ok := trendPoint(export)
		if !ok {
			continue
		}
		points = append(points, localSnapshot{Point: point, Index: readLocalFindingIndex(export.Content)})
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Point.CreatedAt.Equal(points[j].Point.CreatedAt) {
			return points[i].Point.ReportID < points[j].Point.ReportID
		}
		return points[i].Point.CreatedAt.Before(points[j].Point.CreatedAt)
	})
	result.SnapshotCount = len(points)
	if len(points) == 0 {
		return result, nil
	}
	currentSnapshot := points[len(points)-1]
	current := currentSnapshot.Point
	result.Current = &current
	result.State = "BASELINE"
	if len(points) == 1 {
		return result, nil
	}
	previousSnapshot := points[len(points)-2]
	previous := previousSnapshot.Point
	result.Previous = &previous
	result.Delta = metricDelta(previous.Metrics, current.Metrics)
	result.FindingDiff = compareLocalFindingIndexes(previousSnapshot.Index, currentSnapshot.Index)
	metricKeys := []string{"open_finding_count", "critical_count", "coverage_missing_signals", "coverage_unknown_signals", "coverage_percent"}
	if _, previousHasEvidence := previous.Metrics["coverage_evidence_completeness_percent"]; previousHasEvidence {
		if _, currentHasEvidence := current.Metrics["coverage_evidence_completeness_percent"]; currentHasEvidence {
			metricKeys = append(metricKeys, "coverage_evidence_completeness_percent")
		}
	}
	for _, key := range metricKeys {
		delta := result.Delta[key]
		if delta == 0 {
			continue
		}
		regressed := delta > 0
		if key == "coverage_percent" || key == "coverage_evidence_completeness_percent" {
			regressed = delta < 0
		}
		if regressed {
			result.RegressedMetrics = append(result.RegressedMetrics, key)
		} else {
			result.ImprovedMetrics = append(result.ImprovedMetrics, key)
		}
	}
	if result.FindingDiff.Comparable {
		if result.FindingDiff.NewOpen+result.FindingDiff.Reopened > 0 {
			result.RegressedMetrics = append(result.RegressedMetrics, "new_open_findings")
		}
		if result.FindingDiff.Triaged+result.FindingDiff.Cleared > 0 {
			result.ImprovedMetrics = append(result.ImprovedMetrics, "left_open_findings")
		}
	}
	switch {
	case len(result.RegressedMetrics) > 0 && len(result.ImprovedMetrics) > 0:
		result.State = "MIXED"
	case len(result.RegressedMetrics) > 0:
		result.State = "REGRESSED"
	case len(result.ImprovedMetrics) > 0:
		result.State = "IMPROVED"
	default:
		result.State = "STABLE"
	}
	return result, nil
}

func addLocalFindingIndex(content string, findings []model.Finding) (string, error) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return "", err
	}
	items := make([]LocalFindingIndexItem, 0, len(findings))
	for _, finding := range findings {
		items = append(items, LocalFindingIndexItem{ID: finding.ID, Type: finding.Type, Severity: finding.Severity, Status: finding.Status})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	index := localFindingIndex{Complete: len(items) <= localFindingIndexLimit, Count: len(items)}
	if index.Complete {
		index.Items = items
	}
	payload[localFindingIndexKey] = index
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return string(append(encoded, '\n')), nil
}

func readLocalFindingIndex(content string) *localFindingIndex {
	var payload struct {
		Index *localFindingIndex `json:"_local_finding_index"`
	}
	if json.Unmarshal([]byte(content), &payload) != nil {
		return nil
	}
	return payload.Index
}

func compareLocalFindingIndexes(previous, current *localFindingIndex) *LocalFindingDiff {
	result := &LocalFindingDiff{Changes: []LocalFindingChange{}}
	if previous == nil || current == nil {
		result.Reason = "FINDING_INDEX_UNAVAILABLE"
		return result
	}
	result.PreviousCount = previous.Count
	result.CurrentCount = current.Count
	if !previous.Complete || !current.Complete {
		result.Reason = "FINDING_INDEX_TRUNCATED"
		return result
	}
	result.Comparable = true
	previousByID := make(map[string]LocalFindingIndexItem, len(previous.Items))
	currentByID := make(map[string]LocalFindingIndexItem, len(current.Items))
	for _, item := range previous.Items {
		previousByID[item.ID] = item
	}
	for _, item := range current.Items {
		currentByID[item.ID] = item
		prior, found := previousByID[item.ID]
		switch {
		case !found && item.Status == model.FindingStatusOpen:
			result.NewOpen++
			result.addChange(LocalFindingChange{ID: item.ID, Type: item.Type, Severity: item.Severity, To: item.Status, Change: "NEW_OPEN"})
		case found && prior.Status != model.FindingStatusOpen && item.Status == model.FindingStatusOpen:
			result.Reopened++
			result.addChange(LocalFindingChange{ID: item.ID, Type: item.Type, Severity: item.Severity, From: prior.Status, To: item.Status, Change: "REOPENED"})
		case found && prior.Status == model.FindingStatusOpen && item.Status == model.FindingStatusOpen:
			result.PersistentOpen++
		case found && prior.Status == model.FindingStatusOpen && item.Status != model.FindingStatusOpen:
			result.Triaged++
			result.addChange(LocalFindingChange{ID: item.ID, Type: item.Type, Severity: item.Severity, From: prior.Status, To: item.Status, Change: "TRIAGED"})
		}
	}
	for _, item := range previous.Items {
		if _, found := currentByID[item.ID]; !found && item.Status == model.FindingStatusOpen {
			result.Cleared++
			result.addChange(LocalFindingChange{ID: item.ID, Type: item.Type, Severity: item.Severity, From: item.Status, Change: "CLEARED"})
		}
	}
	sort.Slice(result.Changes, func(i, j int) bool {
		if result.Changes[i].Change != result.Changes[j].Change {
			return result.Changes[i].Change < result.Changes[j].Change
		}
		return result.Changes[i].ID < result.Changes[j].ID
	})
	return result
}

func (d *LocalFindingDiff) addChange(change LocalFindingChange) {
	if len(d.Changes) >= localFindingChangeLimit {
		d.ChangesTruncated = true
		return
	}
	d.Changes = append(d.Changes, change)
}
