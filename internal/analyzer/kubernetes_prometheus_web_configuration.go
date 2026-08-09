package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesInvalidPrometheusWebConfigurationAnalyzerID = "builtin.kubernetes_invalid_prometheus_web_configuration"
	KubernetesPrometheusWebConnectionsDisabledAnalyzerID  = "builtin.kubernetes_prometheus_web_connections_disabled"
	KubernetesPlaintextExternalSensitiveAPIAnalyzerID     = "builtin.kubernetes_plaintext_external_prometheus_sensitive_api"
)

type KubernetesInvalidPrometheusWebConfigurationAnalyzer struct{}

func NewKubernetesInvalidPrometheusWebConfigurationAnalyzer() *KubernetesInvalidPrometheusWebConfigurationAnalyzer {
	return &KubernetesInvalidPrometheusWebConfigurationAnalyzer{}
}
func (a *KubernetesInvalidPrometheusWebConfigurationAnalyzer) ID() string {
	return KubernetesInvalidPrometheusWebConfigurationAnalyzerID
}
func (a *KubernetesInvalidPrometheusWebConfigurationAnalyzer) Name() string {
	return "Kubernetes Invalid Prometheus Web Configuration"
}
func (a *KubernetesInvalidPrometheusWebConfigurationAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesInvalidPrometheusWebConfigurationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesInvalidPrometheusWebConfigurationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebConfigurationFindings(ctx, analysis, a.ID(), "invalid")
}

type KubernetesPrometheusWebConnectionsDisabledAnalyzer struct{}

func NewKubernetesPrometheusWebConnectionsDisabledAnalyzer() *KubernetesPrometheusWebConnectionsDisabledAnalyzer {
	return &KubernetesPrometheusWebConnectionsDisabledAnalyzer{}
}
func (a *KubernetesPrometheusWebConnectionsDisabledAnalyzer) ID() string {
	return KubernetesPrometheusWebConnectionsDisabledAnalyzerID
}
func (a *KubernetesPrometheusWebConnectionsDisabledAnalyzer) Name() string {
	return "Kubernetes Prometheus Web Connections Disabled"
}
func (a *KubernetesPrometheusWebConnectionsDisabledAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPrometheusWebConnectionsDisabledAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesPrometheusWebConnectionsDisabledAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebConfigurationFindings(ctx, analysis, a.ID(), "zero")
}

type KubernetesPlaintextExternalSensitiveAPIAnalyzer struct{}

func NewKubernetesPlaintextExternalSensitiveAPIAnalyzer() *KubernetesPlaintextExternalSensitiveAPIAnalyzer {
	return &KubernetesPlaintextExternalSensitiveAPIAnalyzer{}
}
func (a *KubernetesPlaintextExternalSensitiveAPIAnalyzer) ID() string {
	return KubernetesPlaintextExternalSensitiveAPIAnalyzerID
}
func (a *KubernetesPlaintextExternalSensitiveAPIAnalyzer) Name() string {
	return "Kubernetes Plaintext External Prometheus Sensitive API"
}
func (a *KubernetesPlaintextExternalSensitiveAPIAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesPlaintextExternalSensitiveAPIAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTSDB}
}
func (a *KubernetesPlaintextExternalSensitiveAPIAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	return kubernetesPrometheusWebConfigurationFindings(ctx, analysis, a.ID(), "plaintext")
}

func kubernetesPrometheusWebConfigurationFindings(ctx context.Context, analysis Context, analyzerID string, mode string) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTSDB})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		kind := strings.TrimSpace(resource.Metadata["kubernetes_kind"])
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || (kind != "Prometheus" && kind != "PrometheusAgent") {
			continue
		}
		finding, ok := kubernetesPrometheusWebConfigurationFinding(resource, analyzerID, mode, kind, now)
		if ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesPrometheusWebConfigurationFinding(resource model.Resource, analyzerID string, mode string, kind string, now time.Time) (model.Finding, bool) {
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": kind, "namespace": kubernetesResourceNamespace(resource)}
	var findingType string
	var severity model.Severity
	var category model.FindingCategory
	var evidence string
	var recommendation string
	switch mode {
	case "invalid":
		count := kubernetesWebMetadataInt(resource, "prometheus_web_invalid_setting_count")
		if count == 0 {
			return model.Finding{}, false
		}
		findingType, severity, category = "KubernetesInvalidPrometheusWebConfiguration", model.SeverityCritical, model.FindingCategoryConfiguration
		evidence = fmt.Sprintf("Kubernetes %s %q has %d invalid Prometheus web configuration setting(s)", kind, resource.Name, count)
		recommendation = "将 spec.web 配置为对象，并将 maxConnections 设置为非负整数；修复后确认 Operator Reconciled 状态和 Prometheus 启动参数。"
		metadata["prometheus_web_invalid_setting_count"] = strconv.Itoa(count)
	case "zero":
		if resource.Metadata["prometheus_web_max_connections_declared"] != "true" || resource.Metadata["prometheus_web_max_connections_valid"] != "true" || strings.TrimSpace(resource.Metadata["prometheus_web_max_connections"]) != "0" {
			return model.Finding{}, false
		}
		findingType, severity, category = "KubernetesPrometheusWebConnectionsDisabled", model.SeverityCritical, model.FindingCategoryReliability
		evidence = fmt.Sprintf("Kubernetes %s %q sets spec.web.maxConnections=0, so Prometheus accepts no incoming web connections", kind, resource.Name)
		recommendation = "设置经过容量评估的正 maxConnections，或移除该字段使用 Prometheus 默认值；恢复后验证健康检查、查询、写入和配置重载端点。"
		metadata["prometheus_web_max_connections"] = "0"
	case "plaintext":
		admin := resource.Metadata["prometheus_admin_api_enabled"] == "true"
		remote := resource.Metadata["prometheus_remote_write_receiver_enabled"] == "true"
		otlp := resource.Metadata["prometheus_otlp_receiver_enabled"] == "true"
		if resource.Metadata["prometheus_external_url_valid"] != "true" || resource.Metadata["prometheus_external_url_scheme"] != "http" || (!admin && !remote && !otlp) {
			return model.Finding{}, false
		}
		endpoints := make([]string, 0, 3)
		if admin {
			endpoints = append(endpoints, "admin API")
		}
		if remote {
			endpoints = append(endpoints, "remote-write receiver")
		}
		if otlp {
			endpoints = append(endpoints, "OTLP receiver")
		}
		findingType, severity, category = "KubernetesPlaintextExternalPrometheusSensitiveAPI", model.SeverityCritical, model.FindingCategorySecurity
		evidence = fmt.Sprintf("Kubernetes %s %q declares an HTTP external URL while enabling %s", kind, resource.Name, strings.Join(endpoints, ", "))
		recommendation = "将 externalUrl 改为 HTTPS，并在入口代理或 Prometheus Web TLS 配置中启用加密；同时为敏感端点配置认证、授权、网络隔离和请求限制。"
		metadata["prometheus_external_url_scheme"] = "http"
		metadata["sensitive_endpoint_count"] = strconv.Itoa(len(endpoints))
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}

func kubernetesWebMetadataInt(resource model.Resource, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(resource.Metadata[key]))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
