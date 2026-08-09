package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InvalidDatasourceTypeAnalyzerID = "builtin.invalid_datasource_type"

var defaultAllowedDatasourceTypes = []string{
	"alertmanager",
	"cloudwatch",
	"elasticsearch",
	"grafana",
	"graphite",
	"influxdb",
	"loki",
	"mssql",
	"mysql",
	"opentsdb",
	"postgres",
	"prometheus",
	"tempo",
	"testdata",
	"zipkin",
}

type InvalidDatasourceTypeAnalyzer struct{}

func NewInvalidDatasourceTypeAnalyzer() *InvalidDatasourceTypeAnalyzer {
	return &InvalidDatasourceTypeAnalyzer{}
}

func (a *InvalidDatasourceTypeAnalyzer) ID() string {
	return InvalidDatasourceTypeAnalyzerID
}

func (a *InvalidDatasourceTypeAnalyzer) Name() string {
	return "Invalid Datasource Type"
}

func (a *InvalidDatasourceTypeAnalyzer) Version() string {
	return "0.1.0"
}

func (a *InvalidDatasourceTypeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *InvalidDatasourceTypeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowedTypes := datasourceTypeSet(stringSliceConfig(analysis.Config, "allowed_datasource_types", defaultAllowedDatasourceTypes))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		datasourceType := strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceType])
		if datasourceType == "" {
			continue
		}
		normalized := strings.ToLower(datasourceType)
		if allowedTypes[normalized] {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID, normalized),
			Type:     "InvalidDatasourceType",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q has unsupported datasource type %q", datasource.Name, datasourceType),
			},
			Recommendation: "将 Datasource 类型调整为标准值，或通过 allowed_datasource_types 明确加入本地自定义插件类型，避免查询解析和治理聚合出现分歧。",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"datasource_type": datasourceType,
				"allowed_types":   strings.Join(sortedDatasourceTypes(allowedTypes), ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func datasourceTypeSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		result[value] = true
	}
	return result
}

func sortedDatasourceTypes(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
