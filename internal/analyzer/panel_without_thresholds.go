package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PanelWithoutThresholdsAnalyzerID = "builtin.panel_without_thresholds"

var defaultPanelThresholdTypes = []string{"stat", "gauge", "bargauge", "bar gauge"}

type PanelWithoutThresholdsAnalyzer struct{}

func NewPanelWithoutThresholdsAnalyzer() *PanelWithoutThresholdsAnalyzer {
	return &PanelWithoutThresholdsAnalyzer{}
}

func (a *PanelWithoutThresholdsAnalyzer) ID() string {
	return PanelWithoutThresholdsAnalyzerID
}

func (a *PanelWithoutThresholdsAnalyzer) Name() string {
	return "Panel Without Thresholds"
}

func (a *PanelWithoutThresholdsAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PanelWithoutThresholdsAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelWithoutThresholdsAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	requiredTypes := resourceIdentitySet(stringSliceConfig(analysis.Config, "panel_threshold_required_types", defaultPanelThresholdTypes))
	allowed := resourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_panels_without_thresholds", nil))
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
		if panelThresholdCount(panel.Metadata[model.MetadataPanelThresholdCount]) > 0 {
			continue
		}
		if allowedResource(panel, allowed, model.MetadataDashboardUID, model.MetadataPanelID, model.MetadataPanelTitle) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "PanelWithoutThresholds",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana %s panel %q has no threshold metadata", panelType, panel.Name),
			},
			Recommendation: "为状态型或仪表型 Grafana Panel 设置阈值，明确正常/风险/异常边界，减少排障时对数值含义的人工判断；如确认为展示型例外，请加入 allowed_panels_without_thresholds。",
			Metadata: map[string]string{
				"analyzer_id":        a.ID(),
				"visualization_type": panelType,
				"threshold_count":    strings.TrimSpace(panel.Metadata[model.MetadataPanelThresholdCount]),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func panelThresholdCount(raw string) int {
	count, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || count < 0 {
		return 0
	}
	return count
}
