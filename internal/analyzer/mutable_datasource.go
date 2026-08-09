package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MutableDatasourceAnalyzerID = "builtin.mutable_datasource"

type MutableDatasourceAnalyzer struct{}

func NewMutableDatasourceAnalyzer() *MutableDatasourceAnalyzer {
	return &MutableDatasourceAnalyzer{}
}

func (a *MutableDatasourceAnalyzer) ID() string {
	return MutableDatasourceAnalyzerID
}

func (a *MutableDatasourceAnalyzer) Name() string {
	return "Mutable Datasource"
}

func (a *MutableDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MutableDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *MutableDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}

	allowed := datasourceIdentitySet(stringSliceConfig(analysis.Config, "allowed_mutable_datasources", nil))
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if !isActiveDatasource(datasource) {
			continue
		}
		readOnly := strings.ToLower(strings.TrimSpace(datasource.Metadata[model.MetadataDatasourceReadOnly]))
		if readOnly != "false" && readOnly != "0" && readOnly != "no" {
			continue
		}
		if allowedDatasource(datasource, allowed) {
			continue
		}

		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "MutableDatasource",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q is editable in Grafana (readOnly=%s)", datasource.Name, readOnly),
			},
			Recommendation: "生产 Datasource 建议通过 provisioning 或 IaC 管理并设置 readOnly，减少 UI 手工变更导致的数据源漂移；如确认为受控例外，请加入 allowed_mutable_datasources。",
			Metadata: map[string]string{
				"analyzer_id": a.ID(),
				"read_only":   readOnly,
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
