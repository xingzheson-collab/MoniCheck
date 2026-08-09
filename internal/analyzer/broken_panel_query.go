package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BrokenPanelQueryAnalyzerID = "builtin.broken_panel_query"

type BrokenPanelQueryAnalyzer struct{}

func NewBrokenPanelQueryAnalyzer() *BrokenPanelQueryAnalyzer {
	return &BrokenPanelQueryAnalyzer{}
}

func (a *BrokenPanelQueryAnalyzer) ID() string {
	return BrokenPanelQueryAnalyzerID
}

func (a *BrokenPanelQueryAnalyzer) Name() string {
	return "Broken Panel Query"
}

func (a *BrokenPanelQueryAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BrokenPanelQueryAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *BrokenPanelQueryAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) {
			continue
		}
		query := strings.TrimSpace(panel.Metadata[model.MetadataPromQL])
		var findingType string
		var evidence string
		if query == "" {
			findingType = "MissingPanelQuery"
			evidence = fmt.Sprintf("panel %q has no PromQL query metadata", panel.Name)
		} else if len(connector.ExtractPromQLMetricNames(query)) == 0 {
			findingType = "UnresolvedPanelQueryMetric"
			evidence = fmt.Sprintf("panel %q query has no resolvable metric reference", panel.Name)
		}
		if findingType == "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), findingType, panel.ID),
			Type:     findingType,
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence:       []string{evidence},
			Recommendation: "检查 Grafana Panel 的查询配置，确认 PromQL 不为空且引用了有效指标。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
