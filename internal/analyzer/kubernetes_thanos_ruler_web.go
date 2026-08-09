package analyzer

import (
	"context"
	"fmt"
	"sort"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	KubernetesInvalidThanosRulerWebConfigurationAnalyzerID = "builtin.kubernetes_invalid_thanos_ruler_web_configuration"
	KubernetesThanosRulerHTTP2WithoutTLSAnalyzerID         = "builtin.kubernetes_thanos_ruler_http2_without_tls"
)

type KubernetesThanosRulerWebAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerWebConfigurationAnalyzer() *KubernetesThanosRulerWebAnalyzer {
	return &KubernetesThanosRulerWebAnalyzer{id: KubernetesInvalidThanosRulerWebConfigurationAnalyzerID, name: "Kubernetes Invalid ThanosRuler Web Configuration"}
}

func NewKubernetesThanosRulerHTTP2WithoutTLSAnalyzer() *KubernetesThanosRulerWebAnalyzer {
	return &KubernetesThanosRulerWebAnalyzer{id: KubernetesThanosRulerHTTP2WithoutTLSAnalyzerID, name: "Kubernetes ThanosRuler HTTP/2 Without TLS"}
}

func (a *KubernetesThanosRulerWebAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerWebAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerWebAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerWebAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerWebAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_web_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerWebFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerWebFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityCritical
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_web_invalid_setting_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerWebConfigurationAnalyzerID:
		if invalid == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesInvalidThanosRulerWebConfiguration"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d malformed web server setting(s)", resource.Name, invalid)
		recommendation = "将 web/tlsConfig/httpConfig 配置为对象，为 TLS 提供唯一且成对的证书与私钥来源，并使用布尔值配置 http2。"
		metadata["thanos_ruler_web_invalid_setting_count"] = fmt.Sprintf("%d", invalid)
	case KubernetesThanosRulerHTTP2WithoutTLSAnalyzerID:
		if invalid > 0 || resource.Metadata["thanos_ruler_web_http2_valid"] != "true" || resource.Metadata["thanos_ruler_web_http2_enabled"] != "true" || resource.Metadata["thanos_ruler_web_tls_complete"] == "true" {
			return model.Finding{}, false
		}
		severity = model.SeverityWarning
		findingType = "KubernetesThanosRulerHTTP2WithoutTLS"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q enables web HTTP/2 without a complete TLS configuration, so HTTP/2 is disabled", resource.Name)
		recommendation = "配置完整 web.tlsConfig 后再启用 HTTP/2，或显式设置 http2=false，避免清单表达与实际传输协议不一致。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: model.FindingCategoryConfiguration, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
