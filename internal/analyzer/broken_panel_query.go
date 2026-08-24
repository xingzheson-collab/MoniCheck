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
		severity := model.SeverityWarning
		if query == "" {
			findingType = "MissingPanelQuery"
			evidence = fmt.Sprintf("panel %q has no PromQL query metadata", panel.Name)
		} else if len(connector.ExtractPromQLMetricNames(query)) == 0 {
			findingType = "UnresolvedPanelQueryMetric"
			evidence = fmt.Sprintf("panel %q query has no resolvable metric reference", panel.Name)
		} else if missing := missingExactlyBoundMetricDependencies(panel.ID, analysis); missing > 0 {
			findingType = "PanelMetricNotCollected"
			severity = model.SeverityCritical
			evidence = fmt.Sprintf("panel %q has %d metric reference(s) absent from its explicitly bound Prometheus inventory", panel.Name, missing)
		}
		if findingType == "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), findingType, panel.ID),
			Type:     findingType,
			Severity: severity,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence:       []string{evidence},
			Recommendation: panelQueryRecommendation(findingType),
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

func missingExactlyBoundMetricDependencies(resourceID string, analysis Context) int {
	if analysis.Graph == nil {
		return 0
	}
	missing := 0
	for _, relationship := range analysis.Graph.Outgoing(resourceID) {
		if relationship.Type != model.RelationshipUses || relationship.Metadata[model.MetadataMetricInventoryBinding] != "EXACT" {
			continue
		}
		if _, ok := analysis.Graph.Resource(relationship.ToID); !ok {
			missing++
		}
	}
	return missing
}

func panelQueryRecommendation(findingType string) string {
	if findingType == "PanelMetricNotCollected" {
		return "Restore collection for the explicitly bound metric or update the panel query after owner review, then rerun the audit and load the panel against the same datasource."
	}
	return "Inspect the Grafana panel query and confirm that its language, datasource attribution, and metric references can be evaluated."
}
