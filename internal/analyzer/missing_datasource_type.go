package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MissingDatasourceTypeAnalyzerID = "builtin.missing_datasource_type"

type MissingDatasourceTypeAnalyzer struct{}

func NewMissingDatasourceTypeAnalyzer() *MissingDatasourceTypeAnalyzer {
	return &MissingDatasourceTypeAnalyzer{}
}

func (a *MissingDatasourceTypeAnalyzer) ID() string {
	return MissingDatasourceTypeAnalyzerID
}

func (a *MissingDatasourceTypeAnalyzer) Name() string {
	return "Missing Datasource Type"
}

func (a *MissingDatasourceTypeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MissingDatasourceTypeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *MissingDatasourceTypeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		if strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceType]) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "MissingDatasourceType",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q has no datasource type metadata", datasource.Name),
			},
			Recommendation: "为 Datasource 补充类型信息，例如 prometheus、loki、tempo 或 elasticsearch，便于查询解析、风险归类和跨系统治理。",
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

func isActiveDatasource(datasource model.Resource) bool {
	return datasource.Type == model.ResourceTypeDatasource && datasource.Status == model.ResourceStatusActive
}
