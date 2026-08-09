package occurrence

import (
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
)

type Group struct {
	GroupKey         string                      `json:"group_key"`
	AnalyzerID       string                      `json:"analyzer_id"`
	FindingType      string                      `json:"finding_type"`
	Severity         model.Severity              `json:"severity"`
	Category         model.FindingCategory       `json:"category"`
	ResourceType     model.ResourceType          `json:"resource_type"`
	FindingCount     int                         `json:"finding_count"`
	HighestRiskScore int                         `json:"highest_risk_score"`
	FirstSeenAt      time.Time                   `json:"first_seen_at,omitempty"`
	LastSeenAt       time.Time                   `json:"last_seen_at,omitempty"`
	ObservationCount int                         `json:"observation_count"`
	ReopenCount      int                         `json:"reopen_count"`
	StatusCounts     map[model.FindingStatus]int `json:"status_counts"`
	FindingIDs       []string                    `json:"finding_ids"`
}

func GroupKey(finding model.Finding) string {
	return model.StableID(
		"finding-group",
		strings.TrimSpace(finding.Metadata["analyzer_id"]),
		finding.Type,
		string(finding.Severity),
		string(finding.Category),
		string(finding.Resource.Type),
	)
}

func Reconcile(analyzerID string, previous []model.FindingOccurrence, findings []model.Finding, observedAt time.Time) []model.FindingOccurrence {
	observedAt = observedAt.UTC()
	records := make(map[string]model.FindingOccurrence, len(previous)+len(findings))
	for _, record := range previous {
		if record.AnalyzerID == analyzerID {
			records[record.FindingID] = record
		}
	}
	seen := make(map[string]bool, len(findings))
	for _, finding := range findings {
		seen[finding.ID] = true
		record, exists := records[finding.ID]
		if !exists {
			record = model.FindingOccurrence{
				FindingID:        finding.ID,
				FirstSeenAt:      observedAt,
				ObservationCount: 0,
			}
		} else if !record.Active {
			record.ReopenCount++
		}
		record.GroupKey = GroupKey(finding)
		record.AnalyzerID = analyzerID
		record.FindingType = finding.Type
		record.Severity = finding.Severity
		record.Category = finding.Category
		record.ResourceType = finding.Resource.Type
		record.LastSeenAt = observedAt
		record.ObservationCount++
		record.Active = true
		record.ResolvedAt = nil
		records[finding.ID] = record
	}
	for id, record := range records {
		if record.Active && !seen[id] {
			resolvedAt := observedAt
			record.Active = false
			record.ResolvedAt = &resolvedAt
			records[id] = record
		}
	}
	result := make([]model.FindingOccurrence, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FindingID < result[j].FindingID })
	return result
}

func Attach(findings []model.Finding, records []model.FindingOccurrence) []model.Finding {
	byID := make(map[string]model.FindingOccurrence, len(records))
	for _, record := range records {
		byID[record.FindingID] = record
	}
	for index := range findings {
		if record, ok := byID[findings[index].ID]; ok {
			copy := record
			findings[index].Occurrence = &copy
		}
	}
	return findings
}

func BuildGroups(findings []model.Finding) []Group {
	byKey := map[string]*Group{}
	for _, finding := range findings {
		key := GroupKey(finding)
		group := byKey[key]
		if group == nil {
			group = &Group{
				GroupKey: key, AnalyzerID: strings.TrimSpace(finding.Metadata["analyzer_id"]),
				FindingType: finding.Type, Severity: finding.Severity, Category: finding.Category,
				ResourceType: finding.Resource.Type, StatusCounts: map[model.FindingStatus]int{},
			}
			byKey[key] = group
		}
		group.FindingCount++
		group.FindingIDs = append(group.FindingIDs, finding.ID)
		group.StatusCounts[finding.Status]++
		if finding.RiskScore != nil && finding.RiskScore.Score > group.HighestRiskScore {
			group.HighestRiskScore = finding.RiskScore.Score
		}
		if finding.Occurrence != nil {
			record := finding.Occurrence
			if group.FirstSeenAt.IsZero() || record.FirstSeenAt.Before(group.FirstSeenAt) {
				group.FirstSeenAt = record.FirstSeenAt
			}
			if record.LastSeenAt.After(group.LastSeenAt) {
				group.LastSeenAt = record.LastSeenAt
			}
			group.ObservationCount += record.ObservationCount
			group.ReopenCount += record.ReopenCount
		}
	}
	result := make([]Group, 0, len(byKey))
	for _, group := range byKey {
		sort.Strings(group.FindingIDs)
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].HighestRiskScore != result[j].HighestRiskScore {
			return result[i].HighestRiskScore > result[j].HighestRiskScore
		}
		return result[i].GroupKey < result[j].GroupKey
	})
	return result
}
