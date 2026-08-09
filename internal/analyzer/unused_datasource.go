package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const UnusedDatasourceAnalyzerID = "builtin.unused_datasource"

type UnusedDatasourceAnalyzer struct{}

func NewUnusedDatasourceAnalyzer() *UnusedDatasourceAnalyzer {
	return &UnusedDatasourceAnalyzer{}
}

func (a *UnusedDatasourceAnalyzer) ID() string {
	return UnusedDatasourceAnalyzerID
}

func (a *UnusedDatasourceAnalyzer) Name() string {
	return "Unused Datasource"
}

func (a *UnusedDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *UnusedDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *UnusedDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if datasource.Status != model.ResourceStatusActive {
			continue
		}
		if datasourceHasActiveConsumer(datasource.ID, analysis) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "UnusedDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q has no incoming USES relationship", datasource.Name),
			},
			Recommendation: "确认该 Datasource 是否仍被 Dashboard、Panel 或 Alert 使用；若无人使用，建议删除或归档。",
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

func datasourceHasActiveConsumer(datasourceID string, analysis Context) bool {
	for _, relationship := range analysis.Graph.Incoming(datasourceID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		consumer, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || consumer.Status != model.ResourceStatusActive {
			continue
		}
		if isDatasourceConsumerResource(consumer.Type) {
			return true
		}
	}
	return false
}
