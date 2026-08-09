package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PanelWithoutVisualizationTypeAnalyzerID = "builtin.panel_without_visualization_type"

type PanelWithoutVisualizationTypeAnalyzer struct{}

func NewPanelWithoutVisualizationTypeAnalyzer() *PanelWithoutVisualizationTypeAnalyzer {
	return &PanelWithoutVisualizationTypeAnalyzer{}
}

func (a *PanelWithoutVisualizationTypeAnalyzer) ID() string {
	return PanelWithoutVisualizationTypeAnalyzerID
}

func (a *PanelWithoutVisualizationTypeAnalyzer) Name() string {
	return "Panel Without Visualization Type"
}

func (a *PanelWithoutVisualizationTypeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PanelWithoutVisualizationTypeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelWithoutVisualizationTypeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) || strings.TrimSpace(panel.Metadata[model.MetadataVisualizationType]) != "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "PanelWithoutVisualizationType",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana panel %q has no visualization type metadata", panel.Name),
			},
			Recommendation: "检查 Grafana Panel JSON 是否包含 type 字段；缺失时建议修复面板结构或更新采集解析，便于后续按图表类型治理。",
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
