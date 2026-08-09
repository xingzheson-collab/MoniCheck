package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DuplicateDashboardAnalyzerID = "builtin.duplicate_dashboard"

type DuplicateDashboardAnalyzer struct{}

func NewDuplicateDashboardAnalyzer() *DuplicateDashboardAnalyzer {
	return &DuplicateDashboardAnalyzer{}
}

func (a *DuplicateDashboardAnalyzer) ID() string {
	return DuplicateDashboardAnalyzerID
}

func (a *DuplicateDashboardAnalyzer) Name() string {
	return "Duplicate Dashboard"
}

func (a *DuplicateDashboardAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DuplicateDashboardAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDashboard}
}

func (a *DuplicateDashboardAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	dashboards, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDashboard})
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]model.Resource)
	for _, dashboard := range dashboards {
		if !isActiveDashboard(dashboard) {
			continue
		}
		name := normalizeDashboardName(dashboard.Name)
		if name == "" {
			continue
		}
		groups[name] = append(groups[name], dashboard)
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for name, duplicates := range groups {
		if len(duplicates) < 2 {
			continue
		}
		sort.Slice(duplicates, func(i, j int) bool {
			return duplicates[i].ID < duplicates[j].ID
		})

		original := duplicates[0]
		for _, duplicate := range duplicates[1:] {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), name, duplicate.ID),
				Type:     "DuplicateDashboard",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   duplicate.ID,
					Type: duplicate.Type,
					Name: duplicate.Name,
				},
				Evidence: []string{
					fmt.Sprintf("dashboard %q has the same normalized name as %q", duplicate.Name, original.Name),
				},
				Recommendation: "确认重复 Dashboard 是否都需要保留；如果展示内容相近，建议合并或归档冗余看板。",
				Metadata: map[string]string{
					"analyzer_id":            a.ID(),
					"duplicate_of_id":        original.ID,
					"duplicate_of_name":      original.Name,
					"normalized_dashboard":   name,
					"duplicate_dashboard_id": model.StableID(a.ID(), name),
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func normalizeDashboardName(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

func isActiveDashboard(dashboard model.Resource) bool {
	return dashboard.Type == model.ResourceTypeDashboard && dashboard.Status == model.ResourceStatusActive
}
