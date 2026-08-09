package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InsecureDatasourceAnalyzerID = "builtin.insecure_datasource"

type InsecureDatasourceAnalyzer struct{}

func NewInsecureDatasourceAnalyzer() *InsecureDatasourceAnalyzer {
	return &InsecureDatasourceAnalyzer{}
}

func (a *InsecureDatasourceAnalyzer) ID() string {
	return InsecureDatasourceAnalyzerID
}

func (a *InsecureDatasourceAnalyzer) Name() string {
	return "Insecure Datasource"
}

func (a *InsecureDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InsecureDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *InsecureDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowedHosts := datasourceHostSet(stringSliceConfig(analysis.Config, "allowed_insecure_datasource_hosts", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		evidence := insecureDatasourceEvidence(datasource, allowedHosts)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "InsecureDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence:       evidence,
			Recommendation: "公网形态的 Datasource 建议启用 HTTPS/TLS；如确认为受控链路，请将主机加入 allowed_insecure_datasource_hosts。",
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

func insecureDatasourceEvidence(datasource model.Resource, allowedHosts map[string]bool) []string {
	endpoint := datasourceEndpoint(datasource)
	if !endpoint.Configured || !endpoint.Valid || endpoint.HostScope != "public" {
		return nil
	}
	if !strings.EqualFold(endpoint.Scheme, "http") {
		return nil
	}
	if datasourceEndpointAllowed(endpoint, allowedHosts) {
		return nil
	}
	return []string{fmt.Sprintf("configured datasource endpoint uses plain HTTP for a public-looking host (%s)", endpoint.HostFingerprint)}
}
