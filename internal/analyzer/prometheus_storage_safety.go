package analyzer

import (
	"context"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusTSDBWALCompressionDisabledAnalyzerID = "builtin.prometheus_tsdb_wal_compression_disabled"
	PrometheusTSDBLockfileDisabledAnalyzerID       = "builtin.prometheus_tsdb_lockfile_disabled"
	PrometheusAgentLockfileDisabledAnalyzerID      = "builtin.prometheus_agent_lockfile_disabled"
)

type PrometheusStorageSafetyAnalyzer struct {
	id   string
	name string
}

func NewPrometheusTSDBWALCompressionDisabledAnalyzer() *PrometheusStorageSafetyAnalyzer {
	return &PrometheusStorageSafetyAnalyzer{
		id:   PrometheusTSDBWALCompressionDisabledAnalyzerID,
		name: "Prometheus TSDB WAL Compression Disabled",
	}
}

func NewPrometheusTSDBLockfileDisabledAnalyzer() *PrometheusStorageSafetyAnalyzer {
	return &PrometheusStorageSafetyAnalyzer{
		id:   PrometheusTSDBLockfileDisabledAnalyzerID,
		name: "Prometheus TSDB Lockfile Disabled",
	}
}

func NewPrometheusAgentLockfileDisabledAnalyzer() *PrometheusStorageSafetyAnalyzer {
	return &PrometheusStorageSafetyAnalyzer{
		id:   PrometheusAgentLockfileDisabledAnalyzerID,
		name: "Prometheus Agent Lockfile Disabled",
	}
}

func (a *PrometheusStorageSafetyAnalyzer) ID() string      { return a.id }
func (a *PrometheusStorageSafetyAnalyzer) Name() string    { return a.name }
func (a *PrometheusStorageSafetyAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusStorageSafetyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusStorageSafetyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "prometheus" ||
			resource.Status != model.ResourceStatusActive ||
			resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" {
			continue
		}
		isAgent := resource.Metadata[model.MetadataPrometheusAgentMode] == "true"
		if a.id == PrometheusAgentLockfileDisabledAnalyzerID && !isAgent {
			continue
		}
		if a.id != PrometheusAgentLockfileDisabledAnalyzerID && isAgent {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.ID < findings[j].Resource.ID
	})
	return findings, nil
}

func (a *PrometheusStorageSafetyAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusTSDBWALCompressionDisabledAnalyzerID:
		compression, ok := resource.Metadata[model.MetadataPrometheusTSDBWALCompression]
		if !ok || compression != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusTSDBWALCompressionDisabled"
		category = model.FindingCategoryCost
		evidence = "Prometheus server mode is active while TSDB WAL compression is explicitly disabled"
		recommendation = "启用 storage.tsdb.wal-compression，确认无需降级到不支持压缩 WAL 的旧版本后，观察 WAL 磁盘占用和写入 I/O。"
		metadata[model.MetadataPrometheusTSDBWALCompression] = "false"
	case PrometheusTSDBLockfileDisabledAnalyzerID:
		noLockfile, ok := resource.Metadata[model.MetadataPrometheusTSDBNoLockfile]
		if !ok || noLockfile != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusTSDBLockfileDisabled"
		evidence = "Prometheus server mode explicitly disables the TSDB data-directory lockfile"
		recommendation = "关闭 --storage.tsdb.no-lockfile，确保同一数据目录只被一个 Prometheus 进程打开，并检查编排系统不会并发挂载同一可写存储。"
		metadata[model.MetadataPrometheusTSDBNoLockfile] = "true"
	case PrometheusAgentLockfileDisabledAnalyzerID:
		noLockfile, ok := resource.Metadata[model.MetadataPrometheusAgentNoLockfile]
		if !ok || noLockfile != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusAgentLockfileDisabled"
		evidence = "Prometheus Agent mode explicitly disables the Agent data-directory lockfile"
		recommendation = "关闭 --storage.agent.no-lockfile，确保同一 Agent WAL 目录只被一个进程打开，并检查滚动升级不会并发挂载同一可写存储。"
		metadata[model.MetadataPrometheusAgentNoLockfile] = "true"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       model.SeverityWarning,
		Category:       category,
		Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}
