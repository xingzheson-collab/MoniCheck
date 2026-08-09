package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	PrometheusConfigReloadFailedAnalyzerID     = "builtin.prometheus_config_reload_failed"
	PrometheusTSDBCorruptionDetectedAnalyzerID = "builtin.prometheus_tsdb_corruption_detected"
	PrometheusAdminAPIEnabledAnalyzerID        = "builtin.prometheus_admin_api_enabled"
	PrometheusLifecycleAPIEnabledAnalyzerID    = "builtin.prometheus_lifecycle_api_enabled"
	PrometheusRemoteWriteReceiverAnalyzerID    = "builtin.prometheus_remote_write_receiver_enabled"
	PrometheusOTLPReceiverAnalyzerID           = "builtin.prometheus_otlp_receiver_enabled"
)

type PrometheusRuntimeAnalyzer struct {
	id   string
	name string
}

func NewPrometheusConfigReloadFailedAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusConfigReloadFailedAnalyzerID, name: "Prometheus Config Reload Failed"}
}

func NewPrometheusTSDBCorruptionDetectedAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusTSDBCorruptionDetectedAnalyzerID, name: "Prometheus TSDB Corruption Detected"}
}

func NewPrometheusAdminAPIEnabledAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusAdminAPIEnabledAnalyzerID, name: "Prometheus Admin API Enabled"}
}

func NewPrometheusLifecycleAPIEnabledAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusLifecycleAPIEnabledAnalyzerID, name: "Prometheus Lifecycle API Enabled"}
}

func NewPrometheusRemoteWriteReceiverAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusRemoteWriteReceiverAnalyzerID, name: "Prometheus Remote Write Receiver Enabled"}
}

func NewPrometheusOTLPReceiverAnalyzer() *PrometheusRuntimeAnalyzer {
	return &PrometheusRuntimeAnalyzer{id: PrometheusOTLPReceiverAnalyzerID, name: "Prometheus OTLP Receiver Enabled"}
}

func (a *PrometheusRuntimeAnalyzer) ID() string      { return a.id }
func (a *PrometheusRuntimeAnalyzer) Name() string    { return a.name }
func (a *PrometheusRuntimeAnalyzer) Version() string { return "0.1.0" }
func (a *PrometheusRuntimeAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}

func (a *PrometheusRuntimeAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		if finding, ok := a.finding(resource, now); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (a *PrometheusRuntimeAnalyzer) finding(resource model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityCritical
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}

	switch a.id {
	case PrometheusConfigReloadFailedAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusRuntimeAvailable] != "true" {
			return model.Finding{}, false
		}
		if resource.Metadata[model.MetadataPrometheusReloadSuccess] != "false" {
			return model.Finding{}, false
		}
		findingType = "PrometheusConfigReloadFailed"
		category = model.FindingCategoryConfiguration
		evidence = "Prometheus reports that the latest configuration reload failed"
		recommendation = "使用 promtool 校验 Prometheus 配置和规则文件，检查 reload 日志并修复错误；成功重载后重新同步确认状态恢复。"
		if lastConfigAt := resource.Metadata[model.MetadataPrometheusLastConfigAt]; lastConfigAt != "" {
			metadata["last_config_at"] = lastConfigAt
		}
	case PrometheusTSDBCorruptionDetectedAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusRuntimeAvailable] != "true" {
			return model.Finding{}, false
		}
		rawCount, exists := resource.Metadata[model.MetadataPrometheusCorruptionCount]
		if !exists {
			return model.Finding{}, false
		}
		count, err := strconv.ParseInt(rawCount, 10, 64)
		if err != nil || count <= 0 {
			return model.Finding{}, false
		}
		findingType = "PrometheusTSDBCorruptionDetected"
		evidence = fmt.Sprintf("Prometheus runtime reports %d TSDB corruption event(s)", count)
		recommendation = "立即检查 Prometheus 存储日志和磁盘健康，备份可恢复数据，并按官方 TSDB/WAL 恢复流程处理损坏；完成后验证查询与告警数据连续性。"
		metadata["corruption_count"] = strconv.FormatInt(count, 10)
	case PrometheusAdminAPIEnabledAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusAdminAPIEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusAdminAPIEnabled"
		category = model.FindingCategorySecurity
		evidence = "Prometheus admin API is enabled"
		recommendation = "关闭 --web.enable-admin-api；如确需管理 TSDB snapshot、delete-series 或 clean-tombstones，请仅在受控维护窗口通过网络隔离和强认证代理临时开放。"
	case PrometheusLifecycleAPIEnabledAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusLifecycleAPIEnabled] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusLifecycleAPIEnabled"
		severity = model.SeverityWarning
		category = model.FindingCategorySecurity
		evidence = "Prometheus lifecycle API is enabled"
		recommendation = "关闭 --web.enable-lifecycle，或确保 /-/reload 和 /-/quit 只能通过受认证、受审计的内部管理路径访问。"
	case PrometheusRemoteWriteReceiverAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusRemoteWriteReceiver] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusRemoteWriteReceiverEnabled"
		severity = model.SeverityWarning
		category = model.FindingCategoryConfiguration
		evidence = "Prometheus remote-write receiver is enabled"
		recommendation = "仅在经过容量评估的低流量接收场景保留 --web.enable-remote-write-receiver；常规集中写入应使用可水平扩展的 remote storage，并通过认证、授权、网络隔离和请求限流保护 /api/v1/write。"
	case PrometheusOTLPReceiverAnalyzerID:
		if resource.Metadata[model.MetadataPrometheusFlagsAvailable] != "true" ||
			resource.Metadata[model.MetadataPrometheusOTLPReceiver] != "true" {
			return model.Finding{}, false
		}
		findingType = "PrometheusOTLPReceiverEnabled"
		severity = model.SeverityWarning
		category = model.FindingCategoryConfiguration
		evidence = "Prometheus OTLP metrics receiver is enabled"
		recommendation = "仅在经过容量与标签转换评估的低流量场景保留 --web.enable-otlp-receiver；常规 OTLP 接入优先使用 OpenTelemetry Collector 做认证、限流、批处理和转换，再写入可扩展后端。"
	default:
		return model.Finding{}, false
	}

	return model.Finding{
		ID:             model.StableID(a.id, resource.ID),
		Type:           findingType,
		Severity:       severity,
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
