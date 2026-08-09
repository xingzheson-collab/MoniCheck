package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PanelWithoutDatasourceAnalyzerID = "builtin.panel_without_datasource"

type PanelWithoutDatasourceAnalyzer struct{}

func NewPanelWithoutDatasourceAnalyzer() *PanelWithoutDatasourceAnalyzer {
	return &PanelWithoutDatasourceAnalyzer{}
}

func (a *PanelWithoutDatasourceAnalyzer) ID() string {
	return PanelWithoutDatasourceAnalyzerID
}

func (a *PanelWithoutDatasourceAnalyzer) Name() string {
	return "Panel Without Datasource"
}

func (a *PanelWithoutDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PanelWithoutDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelWithoutDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if panel.Status != model.ResourceStatusActive {
			continue
		}
		// New Grafana snapshots carry query-level datasource resolution metadata.
		// Dedicated analyzers provide a more precise result for those panels.
		if _, queryMetadataAvailable := panel.Metadata[model.MetadataPanelQueryCount]; queryMetadataAvailable {
			continue
		}
		if hasDatasourceReference(analysis.Graph.Outgoing(panel.ID), analysis.Graph) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), panel.ID),
			Type:     "PanelWithoutDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("panel %q has no datasource dependency relationship", panel.Name),
			},
			Recommendation: "检查 Grafana Panel 的 datasource 配置和采集解析结果，确保面板查询绑定到有效 Datasource。",
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

func hasDatasourceReference(relationships []model.Relationship, resourceGraph interface {
	Resource(id string) (model.Resource, bool)
}) bool {
	for _, relationship := range relationships {
		switch relationship.Type {
		case model.RelationshipUses, model.RelationshipReferences, model.RelationshipDependsOn:
		default:
			continue
		}
		resource, ok := resourceGraph.Resource(relationship.ToID)
		if ok && resource.Type == model.ResourceTypeDatasource && resource.Status == model.ResourceStatusActive {
			return true
		}
	}
	return false
}
