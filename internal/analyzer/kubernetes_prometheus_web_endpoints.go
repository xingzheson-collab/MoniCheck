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

const (
	KubernetesPrometheusAdminAPIEnabledAnalyzerID  = "builtin.kubernetes_prometheus_admin_api_enabled"
	KubernetesRemoteWriteReceiverEnabledAnalyzerID = "builtin.kubernetes_remote_write_receiver_enabled"
	KubernetesOTLPReceiverEnabledAnalyzerID        = "builtin.kubernetes_otlp_receiver_enabled"
	KubernetesUnsupportedReceiverVersionAnalyzerID = "builtin.kubernetes_unsupported_prometheus_receiver_version"
)

type KubernetesPrometheusAdminAPIEnabledAnalyzer struct{}

func NewKubernetesPrometheusAdminAPIEnabledAnalyzer() *KubernetesPrometheusAdminAPIEnabledAnalyzer {
	return &KubernetesPrometheusAdminAPIEnabledAnalyzer{}
}
func (a *KubernetesPrometheusAdminAPIEnabledAnalyzer) ID() string {
	return KubernetesPrometheusAdminAPIEnabledAnalyzerID
}
func (a *KubernetesPrometheusAdminAPIEnabledAnalyzer) Name() string {
	return "Kubernetes Prometheus Admin API Enabled"
}
func (a *KubernetesPrometheusAdminAPIEnabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusAdminAPIEnabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesPrometheusAdminAPIEnabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebEndpointFindings(ctx, analysis, a.ID(), "KubernetesPrometheusAdminAPIEnabled", "prometheus_admin_api_enabled", false)
}

type KubernetesRemoteWriteReceiverEnabledAnalyzer struct{}

func NewKubernetesRemoteWriteReceiverEnabledAnalyzer() *KubernetesRemoteWriteReceiverEnabledAnalyzer {
	return &KubernetesRemoteWriteReceiverEnabledAnalyzer{}
}
func (a *KubernetesRemoteWriteReceiverEnabledAnalyzer) ID() string {
	return KubernetesRemoteWriteReceiverEnabledAnalyzerID
}
func (a *KubernetesRemoteWriteReceiverEnabledAnalyzer) Name() string {
	return "Kubernetes Prometheus Remote Write Receiver Enabled"
}
func (a *KubernetesRemoteWriteReceiverEnabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesRemoteWriteReceiverEnabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesRemoteWriteReceiverEnabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebEndpointFindings(ctx, analysis, a.ID(), "KubernetesRemoteWriteReceiverEnabled", "prometheus_remote_write_receiver_enabled", true)
}

type KubernetesOTLPReceiverEnabledAnalyzer struct{}

func NewKubernetesOTLPReceiverEnabledAnalyzer() *KubernetesOTLPReceiverEnabledAnalyzer {
	return &KubernetesOTLPReceiverEnabledAnalyzer{}
}
func (a *KubernetesOTLPReceiverEnabledAnalyzer) ID() string {
	return KubernetesOTLPReceiverEnabledAnalyzerID
}
func (a *KubernetesOTLPReceiverEnabledAnalyzer) Name() string {
	return "Kubernetes Prometheus OTLP Receiver Enabled"
}
func (a *KubernetesOTLPReceiverEnabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesOTLPReceiverEnabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesOTLPReceiverEnabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebEndpointFindings(ctx, analysis, a.ID(), "KubernetesOTLPReceiverEnabled", "prometheus_otlp_receiver_enabled", true)
}

type KubernetesUnsupportedReceiverVersionAnalyzer struct{}

func NewKubernetesUnsupportedReceiverVersionAnalyzer() *KubernetesUnsupportedReceiverVersionAnalyzer {
	return &KubernetesUnsupportedReceiverVersionAnalyzer{}
}
func (a *KubernetesUnsupportedReceiverVersionAnalyzer) ID() string {
	return KubernetesUnsupportedReceiverVersionAnalyzerID
}
func (a *KubernetesUnsupportedReceiverVersionAnalyzer) Name() string {
	return "Kubernetes Unsupported Prometheus Receiver Version"
}
func (a *KubernetesUnsupportedReceiverVersionAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesUnsupportedReceiverVersionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesUnsupportedReceiverVersionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		remoteUnsupported := resource.Metadata["prometheus_remote_write_receiver_version_unsupported"] == "true"
		otlpUnsupported := resource.Metadata["prometheus_otlp_receiver_version_unsupported"] == "true"
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") || (!remoteUnsupported && !otlpUnsupported) {
			continue
		}
		incompatible := make([]string, 0, 2)
		if remoteUnsupported {
			incompatible = append(incompatible, "remote-write receiver (requires Prometheus >= 2.33)")
		}
		if otlpUnsupported {
			incompatible = append(incompatible, "OTLP receiver (requires Prometheus >= 2.47)")
		}
		version := strings.TrimSpace(resource.Metadata["prometheus_version"])
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "KubernetesUnsupportedPrometheusReceiverVersion", Severity: model.SeverityCritical, Category: model.FindingCategoryReliability,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("Kubernetes %s %q declares Prometheus version %q with unsupported %s", kind, resource.Name, version, strings.Join(incompatible, " and "))},
			Recommendation: "升级 spec.version 到所有已启用 receiver 所需的最低 Prometheus 版本或更高版本，或关闭不兼容的入站端点；随后确认 Operator Reconciled 状态和 Pod 启动参数。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource), "prometheus_version": version, "remote_write_receiver_unsupported": fmt.Sprintf("%t", remoteUnsupported), "otlp_receiver_unsupported": fmt.Sprintf("%t", otlpUnsupported)},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusWebEndpointFindings(ctx context.Context, analysis Context, analyzerID string, findingType string, metadataKey string, includeAgent bool) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		kindAllowed := kind == "Prometheus" || (includeAgent && kind == "PrometheusAgent")
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || !kindAllowed || resource.Metadata[metadataKey] != "true" {
			continue
		}
		severity := model.SeverityWarning
		category := model.FindingCategoryConfiguration
		evidence := fmt.Sprintf("Kubernetes %s %q has spec.enableRemoteWriteReceiver=true, enabling the /api/v1/write ingestion endpoint", kind, resource.Name)
		recommendation := "仅在经过容量评估的低流量接收场景保留该端点；常规集中写入应使用可水平扩展的 remote storage，并通过认证、授权、网络策略和请求限流保护接收路径。"
		if metadataKey == "prometheus_admin_api_enabled" {
			severity = model.SeverityCritical
			category = model.FindingCategorySecurity
			evidence = fmt.Sprintf("Kubernetes Prometheus %q has spec.enableAdminAPI=true, enabling mutating TSDB administration endpoints", resource.Name)
			recommendation = "除非存在受审计的运维需求，否则关闭 enableAdminAPI；必须启用时，在端点前增加强认证、细粒度授权和网络隔离，并限制 delete_series、clean_tombstones 等变更操作。"
		} else if metadataKey == "prometheus_otlp_receiver_enabled" {
			source := "spec.enableOTLPReceiver=true"
			if resource.Metadata["prometheus_otlp_config_declared"] == "true" {
				source = "spec.otlp is declared"
			}
			evidence = fmt.Sprintf("Kubernetes %s %q enables the Prometheus OTLP metrics receiver because %s", kind, resource.Name, source)
			recommendation = "仅在经过容量与标签转换评估的低流量场景保留 Prometheus OTLP receiver；常规 OTLP 接入优先使用 OpenTelemetry Collector 做认证、限流、批处理和转换，再写入可扩展后端。"
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation,
			Metadata: map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource), metadataKey: "true"},
			Status:   model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}
