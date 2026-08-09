package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const BasicAuthHTTPDatasourceAnalyzerID = "builtin.basic_auth_http_datasource"

type BasicAuthHTTPDatasourceAnalyzer struct{}

func NewBasicAuthHTTPDatasourceAnalyzer() *BasicAuthHTTPDatasourceAnalyzer {
	return &BasicAuthHTTPDatasourceAnalyzer{}
}

func (a *BasicAuthHTTPDatasourceAnalyzer) ID() string {
	return BasicAuthHTTPDatasourceAnalyzerID
}

func (a *BasicAuthHTTPDatasourceAnalyzer) Name() string {
	return "Basic Auth HTTP Datasource"
}

func (a *BasicAuthHTTPDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *BasicAuthHTTPDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *BasicAuthHTTPDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowed := datasourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_basic_auth_http_datasources", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		if !isTruthy(datasource.Metadata[model.MetadataDatasourceBasicAuth]) {
			continue
		}
		endpoint := datasourceEndpoint(datasource)
		if !endpoint.Valid || !strings.EqualFold(endpoint.Scheme, "http") {
			continue
		}
		if allowedDatasource(datasource, allowed) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "BasicAuthHTTPDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q uses basic auth over a plain HTTP endpoint", datasource.Name),
			},
			Recommendation: "启用 HTTPS/TLS 或改用更安全的认证/网络链路，避免 Basic Auth 凭据在明文 HTTP 链路上传输；如确认为隔离网络例外，请加入 allowed_basic_auth_http_datasources。",
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

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
