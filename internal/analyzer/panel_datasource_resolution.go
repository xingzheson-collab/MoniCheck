package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	UnresolvedPanelDatasourceAnalyzerID      = "builtin.unresolved_panel_datasource"
	PanelQueryWithoutDatasourceAnalyzerID    = "builtin.panel_query_without_datasource"
	PanelQueryDependencyParseErrorAnalyzerID = "builtin.panel_query_dependency_parse_error"
)

type UnresolvedPanelDatasourceAnalyzer struct{}

func NewUnresolvedPanelDatasourceAnalyzer() *UnresolvedPanelDatasourceAnalyzer {
	return &UnresolvedPanelDatasourceAnalyzer{}
}

func (a *UnresolvedPanelDatasourceAnalyzer) ID() string      { return UnresolvedPanelDatasourceAnalyzerID }
func (a *UnresolvedPanelDatasourceAnalyzer) Name() string    { return "Unresolved Panel Datasource" }
func (a *UnresolvedPanelDatasourceAnalyzer) Version() string { return "0.1.0" }
func (a *UnresolvedPanelDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *UnresolvedPanelDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return panelDatasourceCountFindings(
		ctx,
		analysis,
		a.ID(),
		model.MetadataPanelUnresolvedDatasourceCount,
		"UnresolvedPanelDatasource",
		model.SeverityWarning,
		"contains %d query datasource reference(s) that do not resolve to a discovered Grafana datasource",
		"修复或重新绑定 Grafana Panel 中失效的数据源引用；对于 Mixed Panel，应逐个检查 target 的 datasource UID 或名称。",
	)
}

type PanelQueryWithoutDatasourceAnalyzer struct{}

func NewPanelQueryWithoutDatasourceAnalyzer() *PanelQueryWithoutDatasourceAnalyzer {
	return &PanelQueryWithoutDatasourceAnalyzer{}
}

func (a *PanelQueryWithoutDatasourceAnalyzer) ID() string {
	return PanelQueryWithoutDatasourceAnalyzerID
}
func (a *PanelQueryWithoutDatasourceAnalyzer) Name() string {
	return "Panel Query Without Datasource"
}
func (a *PanelQueryWithoutDatasourceAnalyzer) Version() string { return "0.1.0" }
func (a *PanelQueryWithoutDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelQueryWithoutDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return panelDatasourceCountFindings(
		ctx,
		analysis,
		a.ID(),
		model.MetadataPanelQueryWithoutDatasource,
		"PanelQueryWithoutDatasource",
		model.SeverityWarning,
		"contains %d query target(s) without an effective datasource",
		"为 Grafana Panel 的查询绑定有效数据源；Mixed Panel 必须在每个非表达式 target 上显式选择 datasource。",
	)
}

type PanelQueryDependencyParseErrorAnalyzer struct{}

func NewPanelQueryDependencyParseErrorAnalyzer() *PanelQueryDependencyParseErrorAnalyzer {
	return &PanelQueryDependencyParseErrorAnalyzer{}
}

func (a *PanelQueryDependencyParseErrorAnalyzer) ID() string {
	return PanelQueryDependencyParseErrorAnalyzerID
}
func (a *PanelQueryDependencyParseErrorAnalyzer) Name() string {
	return "Panel Query Dependency Parse Error"
}
func (a *PanelQueryDependencyParseErrorAnalyzer) Version() string { return "0.1.0" }
func (a *PanelQueryDependencyParseErrorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel}
}

func (a *PanelQueryDependencyParseErrorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return panelDatasourceCountFindings(
		ctx,
		analysis,
		a.ID(),
		model.MetadataPanelDependencyParseErrorCount,
		"PanelQueryDependencyParseError",
		model.SeverityWarning,
		"contains %d supported query target(s) whose dependency structure could not be parsed",
		"检查 Grafana Panel 的 LogQL、TraceQL 或 SQL 查询语法；修复未闭合 selector、引号、注释或不完整查询后重新同步。",
	)
}

func panelDatasourceCountFindings(
	ctx context.Context,
	analysis Context,
	analyzerID string,
	metadataKey string,
	findingType string,
	severity model.Severity,
	evidenceFormat string,
	recommendation string,
) ([]model.Finding, error) {
	panels, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypePanel})
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, panel := range panels {
		if !isActiveGrafanaPanel(panel) {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(panel.Metadata[metadataKey]))
		if err != nil || count <= 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(analyzerID, panel.ID),
			Type:     findingType,
			Severity: severity,
			Resource: model.ResourceRef{
				ID:   panel.ID,
				Type: panel.Type,
				Name: panel.Name,
			},
			Evidence: []string{
				fmt.Sprintf("grafana panel %q "+evidenceFormat, panel.Name, count),
			},
			Recommendation: recommendation,
			Metadata: map[string]string{
				"analyzer_id": analyzerID,
				"count":       strconv.Itoa(count),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}
