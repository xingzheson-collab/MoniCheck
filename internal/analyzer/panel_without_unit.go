package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PanelWithoutUnitAnalyzerID = "builtin.panel_without_unit"

var defaultPanelUnitTypes = []string{"timeseries", "stat", "gauge", "bargauge", "bar gauge", "graph"}

type PanelWithoutUnitAnalyzer struct{}

func NewPanelWithoutUnitAnalyzer() *PanelWithoutUnitAnalyzer {
	return &PanelWithoutUnitAnalyzer{}
}

func (a *PanelWithoutUnitAnalyzer) ID() string {
	return PanelWithoutUnitAnalyzerID
}

func (a *PanelWithoutUnitAnalyzer) Name() string {
	return "Panel Without Unit"
}

func (a *PanelWithoutUnitAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PanelWithoutUnitAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelWithoutUnitAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	requiredTypes := resourceIdentitySet(stringSliceConfig(analysis.Config, "panel_unit_required_types", defaultPanelUnitTypes))
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_panels_without_unit", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) {
			continue
		}
		panelType := strings.ToLower(strings.TrimSpace(panel.Metadata[model.MetadataVisualizationType]))
		if panelType == "" || !requiredTypes[panelType] {
			continue
		}
		if hasSemanticPanelUnit(panel.Metadata[model.MetadataPanelUnit]) {
			continue
		}
		if allowedResource(panel, allowed, model.MetadataDashboardUID, model.MetadataPanelID, model.MetadataPanelTitle) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "PanelWithoutUnit",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana %s panel %q has no semantic unit metadata", panelType, panel.Name),
			},
			Recommendation: "为数值型 Grafana Panel 设置明确单位，避免读图时混淆 QPS、延迟、比例、字节等语义；如确认为无单位指标，请加入 allowed_panels_without_unit。",
			Metadata: map[string]string{
				"analyzer_id":        a.ID(),
				"visualization_type": panelType,
				"unit":               strings.TrimSpace(panel.Metadata[model.MetadataPanelUnit]),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func hasSemanticPanelUnit(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none", "short":
		return false
	default:
		return true
	}
}
