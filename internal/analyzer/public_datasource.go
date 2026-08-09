package analyzer

import (
	"context"
	"fmt"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const PublicDatasourceAnalyzerID = "builtin.public_datasource"

type PublicDatasourceAnalyzer struct{}

func NewPublicDatasourceAnalyzer() *PublicDatasourceAnalyzer {
	return &PublicDatasourceAnalyzer{}
}

func (a *PublicDatasourceAnalyzer) ID() string {
	return PublicDatasourceAnalyzerID
}

func (a *PublicDatasourceAnalyzer) Name() string {
	return "Public Datasource"
}

func (a *PublicDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PublicDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *PublicDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowedHosts := datasourceHostSet(stringSliceConfig(analysis.Config, "allowed_public_datasource_hosts", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		evidence := publicDatasourceEvidence(datasource, allowedHosts)
		if len(evidence) == 0 {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "PublicDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence:       evidence,
			Recommendation: "确认该 Datasource 是否应暴露到公网或公网域名；生产监控数据源建议使用私网地址、专线/VPN 或明确加入 allowlist。",
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

func publicDatasourceEvidence(datasource model.Resource, allowedHosts map[string]bool) []string {
	endpoint := datasourceEndpoint(datasource)
	if !endpoint.Configured || !endpoint.Valid || endpoint.HostScope != "public" {
		return nil
	}
	if datasourceEndpointAllowed(endpoint, allowedHosts) {
		return nil
	}
	return []string{fmt.Sprintf("configured datasource endpoint resolves to a public-looking host (%s)", endpoint.HostFingerprint)}
}
