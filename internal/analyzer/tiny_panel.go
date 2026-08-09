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

const TinyPanelAnalyzerID = "builtin.tiny_panel"

const defaultTinyPanelAreaThreshold = 8

type TinyPanelAnalyzer struct{}

func NewTinyPanelAnalyzer() *TinyPanelAnalyzer {
	return &TinyPanelAnalyzer{}
}

func (a *TinyPanelAnalyzer) ID() string {
	return TinyPanelAnalyzerID
}

func (a *TinyPanelAnalyzer) Name() string {
	return "Tiny Panel"
}

func (a *TinyPanelAnalyzer) Version() string {
	return "0.1.0"
}

func (a *TinyPanelAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *TinyPanelAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	threshold := intConfig(analysis.Config, "tiny_panel_area_threshold", defaultTinyPanelAreaThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) {
			continue
		}
		width, height, ok := panelGridSize(panel.Metadata)
		if !ok {
			continue
		}
		area := width * height
		if area >= threshold {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "TinyPanel",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana panel %q grid size is %dx%d (area %d), threshold is %d", panel.Name, width, height, area, threshold),
			},
			Recommendation: "检查该 Panel 是否过小导致信息不可读；建议合并到相邻面板、调整布局或移除低价值小面板。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"area":        strconv.Itoa(area),
				"threshold":   strconv.Itoa(threshold),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func panelGridSize(metadata map[string]string) (int, int, bool) {
	width, err := strconv.Atoi(strings.TrimSpace(metadata[model.MetadataPanelGridW]))
	if err != nil || width <= 0 {
		return 0, 0, false
	}
	height, err := strconv.Atoi(strings.TrimSpace(metadata[model.MetadataPanelGridH]))
	if err != nil || height <= 0 {
		return 0, 0, false
	}
	return width, height, true
}
