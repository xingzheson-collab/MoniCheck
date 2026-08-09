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

const MultipleDefaultDatasourceAnalyzerID = "builtin.multiple_default_datasource"

type MultipleDefaultDatasourceAnalyzer struct{}

func NewMultipleDefaultDatasourceAnalyzer() *MultipleDefaultDatasourceAnalyzer {
	return &MultipleDefaultDatasourceAnalyzer{}
}

func (a *MultipleDefaultDatasourceAnalyzer) ID() string {
	return MultipleDefaultDatasourceAnalyzerID
}

func (a *MultipleDefaultDatasourceAnalyzer) Name() string {
	return "Multiple Default Datasource"
}

func (a *MultipleDefaultDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MultipleDefaultDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *MultipleDefaultDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	defaultsByInstance := make(map[string][]model.Resource)
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) || datasource.Source.System != "grafana" || !isTruthy(datasource.Metadata[model.MetadataDatasourceDefault]) {
			continue
		}
		key := datasource.Source.Instance
		defaultsByInstance[key] = append(defaultsByInstance[key], datasource)
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for instance, defaults := range defaultsByInstance {
		if len(defaults) <= 1 {
			continue
		}
		names := datasourceNames(defaults)
		for _, datasource := range defaults {
			findings = append(findings, model.Finding{
				ID:       model.StableID(a.ID(), datasource.ID, strings.Join(names, ",")),
				Type:     "MultipleDefaultDatasource",
				Severity: model.SeverityWarning,
				Resource: model.ResourceRef{
					ID:   datasource.ID,
					Type: datasource.Type,
					Name: datasource.Name,
				},
				Evidence: []string{
					fmt.Sprintf("grafana instance %q has multiple default datasources: %s", instance, strings.Join(names, ", ")),
				},
				Recommendation: "保留一个明确的默认 Datasource，避免新建面板、变量或告警规则时隐式选择错误数据源。",
				Metadata: map[string]string{
					"analyzer_id":         a.ID(),
					"default_datasources": strings.Join(names, ","),
					"grafana_instance":    instance,
				},
				Status:    model.FindingStatusOpen,
				CreatedAt: now,
				UpdatedAt: now,
			})
		}
	}
	return findings, nil
}

func datasourceNames(datasources []model.Resource) []string {
	names := make([]string, 0, len(datasources))
	for _, datasource := range datasources {
		names = append(names, datasource.Name)
	}
	sort.Strings(names)
	return names
}
