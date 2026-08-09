package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PanelWithoutTitleAnalyzerID = "builtin.panel_without_title"

type PanelWithoutTitleAnalyzer struct{}

func NewPanelWithoutTitleAnalyzer() *PanelWithoutTitleAnalyzer {
	return &PanelWithoutTitleAnalyzer{}
}

func (a *PanelWithoutTitleAnalyzer) ID() string {
	return PanelWithoutTitleAnalyzerID
}

func (a *PanelWithoutTitleAnalyzer) Name() string {
	return "Panel Without Title"
}

func (a *PanelWithoutTitleAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PanelWithoutTitleAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelWithoutTitleAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) || strings.TrimSpace(panel.Metadata[model.MetadataPanelTitle]) != "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "PanelWithoutTitle",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana panel %q has no title metadata", panel.Name),
			},
			Recommendation: "为 Grafana Panel 设置清晰标题，便于 Dashboard 扫描、告警排查和面板级治理；如果是纯装饰面板，请确认是否仍有保留价值。",
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
