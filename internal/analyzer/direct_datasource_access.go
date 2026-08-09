package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DirectDatasourceAccessAnalyzerID = "builtin.direct_datasource_access"

type DirectDatasourceAccessAnalyzer struct{}

func NewDirectDatasourceAccessAnalyzer() *DirectDatasourceAccessAnalyzer {
	return &DirectDatasourceAccessAnalyzer{}
}

func (a *DirectDatasourceAccessAnalyzer) ID() string {
	return DirectDatasourceAccessAnalyzerID
}

func (a *DirectDatasourceAccessAnalyzer) Name() string {
	return "Direct Datasource Access"
}

func (a *DirectDatasourceAccessAnalyzer) Version() string {
	return "0.1.0"
}

func (a *DirectDatasourceAccessAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *DirectDatasourceAccessAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowed := datasourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_direct_datasource_access", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		access := strings.ToLower(strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceAccess]))
		if access != "direct" && access != "browser" {
			continue
		}
		if allowedDatasource(datasource, allowed) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID, access),
			Type:     "DirectDatasourceAccess",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q uses %q access mode", datasource.Name, access),
			},
			Recommendation: "优先使用 Grafana proxy/server access，避免用户浏览器直接访问监控数据源地址；如确认为受控场景，请加入 allowed_direct_datasource_access。",
			Metadata: map[string]string{
				"analyzer_id":       a.ID(),
				"datasource_access": access,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func datasourceIdentitySet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result[value] = true
		}
	}
	return result
}

func allowedDatasource(datasource model.Resource, allowed map[string]bool) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, value := range []string{
		datasource.ID,
		datasource.Name,
		datasource.UID,
		datasource.Metadata[model.MetadataDatasourceUID],
	} {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && allowed[value] {
			return true
		}
	}
	return false
}
