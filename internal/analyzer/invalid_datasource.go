package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InvalidDatasourceAnalyzerID = "builtin.invalid_datasource"

type InvalidDatasourceAnalyzer struct{}

func NewInvalidDatasourceAnalyzer() *InvalidDatasourceAnalyzer {
	return &InvalidDatasourceAnalyzer{}
}

func (a *InvalidDatasourceAnalyzer) ID() string {
	return InvalidDatasourceAnalyzerID
}

func (a *InvalidDatasourceAnalyzer) Name() string {
	return "Invalid Datasource"
}

func (a *InvalidDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InvalidDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *InvalidDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isDatasourceEligibleForHealthDetection(datasource) {
			continue
		}
		evidence := datasourceEvidence(datasource)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "InvalidDatasource",
			Severity: model.SeverityCritical,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence:       evidence,
			Recommendation: "检查 Datasource 配置、URL、凭据和 Grafana 侧连通性；若长期失效，建议删除或归档。",
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

func datasourceEvidence(datasource model.Resource) []string {
	evidence := make([]string, 0, 3)
	health := strings.TrimSpace(datasource.Metadata[model.MetadataHealth])
	if health != "" && !strings.EqualFold(health, "ok") && !strings.EqualFold(health, "up") {
		evidence = append(evidence, fmt.Sprintf("datasource health is %q", health))
	}
	if datasource.Status == model.ResourceStatusBroken {
		evidence = append(evidence, fmt.Sprintf("datasource status is %s", datasource.Status))
	}

	endpoint := datasourceEndpoint(datasource)
	if !endpoint.Configured {
		evidence = append(evidence, "datasource url is empty")
		return evidence
	}
	if !endpoint.Valid {
		evidence = append(evidence, "configured datasource endpoint is invalid")
	}
	return evidence
}

func isDatasourceEligibleForHealthDetection(datasource model.Resource) bool {
	return datasource.Type == model.ResourceTypeDatasource &&
		datasource.Metadata[model.MetadataDatasourceHealthEvaluable] != "false" &&
		datasource.Status != model.ResourceStatusDeprecated &&
		datasource.Status != model.ResourceStatusDeleted
}
