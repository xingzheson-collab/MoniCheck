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
	KubernetesInvalidThanosRulerGRPCTLSAnalyzerID     = "builtin.kubernetes_invalid_thanos_ruler_grpc_tls"
	KubernetesUnsupportedThanosRulerGRPCTLSAnalyzerID = "builtin.kubernetes_unsupported_thanos_ruler_grpc_tls_fields"
	KubernetesThanosRulerWithoutGRPCTLSAnalyzerID     = "builtin.kubernetes_thanos_ruler_without_grpc_tls"
)

type KubernetesThanosRulerGRPCTLSAnalyzer struct {
	id   string
	name string
}

func NewKubernetesInvalidThanosRulerGRPCTLSAnalyzer() *KubernetesThanosRulerGRPCTLSAnalyzer {
	return &KubernetesThanosRulerGRPCTLSAnalyzer{id: KubernetesInvalidThanosRulerGRPCTLSAnalyzerID, name: "Kubernetes Invalid ThanosRuler gRPC TLS"}
}
func NewKubernetesUnsupportedThanosRulerGRPCTLSAnalyzer() *KubernetesThanosRulerGRPCTLSAnalyzer {
	return &KubernetesThanosRulerGRPCTLSAnalyzer{id: KubernetesUnsupportedThanosRulerGRPCTLSAnalyzerID, name: "Kubernetes Unsupported ThanosRuler gRPC TLS Fields"}
}
func NewKubernetesThanosRulerWithoutGRPCTLSAnalyzer() *KubernetesThanosRulerGRPCTLSAnalyzer {
	return &KubernetesThanosRulerGRPCTLSAnalyzer{id: KubernetesThanosRulerWithoutGRPCTLSAnalyzerID, name: "Kubernetes ThanosRuler Without gRPC TLS"}
}
func (a *KubernetesThanosRulerGRPCTLSAnalyzer) ID() string      { return a.id }
func (a *KubernetesThanosRulerGRPCTLSAnalyzer) Name() string    { return a.name }
func (a *KubernetesThanosRulerGRPCTLSAnalyzer) Version() string { return "0.1.0" }
func (a *KubernetesThanosRulerGRPCTLSAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeInstance}
}

func (a *KubernetesThanosRulerGRPCTLSAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeInstance})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Source.System != "kubernetes" || resource.Status != model.ResourceStatusActive || resource.Metadata["kubernetes_kind"] != "ThanosRuler" || resource.Metadata["thanos_ruler_grpc_tls_metadata"] != "true" {
			continue
		}
		if finding, matched := kubernetesThanosRulerGRPCTLSFinding(a.id, resource, now); matched {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Resource.ID < findings[j].Resource.ID })
	return findings, nil
}

func kubernetesThanosRulerGRPCTLSFinding(analyzerID string, resource model.Resource, now time.Time) (model.Finding, bool) {
	severity := model.SeverityWarning
	category := model.FindingCategoryConfiguration
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": analyzerID, "kubernetes_kind": "ThanosRuler", "namespace": kubernetesResourceNamespace(resource)}
	invalid := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_grpc_tls_invalid_setting_count")
	unsupported := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_grpc_tls_unsupported_setting_count")
	switch analyzerID {
	case KubernetesInvalidThanosRulerGRPCTLSAnalyzerID:
		if invalid == 0 {
			return model.Finding{}, false
		}
		severity = model.SeverityCritical
		findingType = "KubernetesInvalidThanosRulerGRPCTLS"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d malformed or incomplete gRPC TLS setting(s)", resource.Name, invalid)
		recommendation = "为 grpcServerTlsConfig 提供非空 certFile/keyFile，使用有效 TLS 版本及唯一非空 cipher/curve 列表，并验证 Operator 调谐。"
		metadata["thanos_ruler_grpc_tls_invalid_setting_count"] = fmt.Sprintf("%d", invalid)
	case KubernetesUnsupportedThanosRulerGRPCTLSAnalyzerID:
		if unsupported == 0 {
			return model.Finding{}, false
		}
		findingType = "KubernetesUnsupportedThanosRulerGRPCTLSFields"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q declares %d gRPC TLS field(s) not supported by the Operator's ThanosRuler integration", resource.Name, unsupported)
		recommendation = "迁移到受支持的 caFile/certFile/keyFile、minVersion、cipherSuites 和 curves 字段，并确认生成 StatefulSet 参数实际启用 TLS。"
		metadata["thanos_ruler_grpc_tls_unsupported_setting_count"] = fmt.Sprintf("%d", unsupported)
	case KubernetesThanosRulerWithoutGRPCTLSAnalyzerID:
		replicas := alertmanagerStorageMetadataInt64(resource, "thanos_ruler_replicas")
		if resource.Metadata["thanos_ruler_grpc_tls_declared"] == "true" || replicas <= 0 || (resource.Metadata["thanos_ruler_listen_local_valid"] == "true" && resource.Metadata["thanos_ruler_listen_local_enabled"] == "true") {
			return model.Finding{}, false
		}
		category = model.FindingCategoryReliability
		findingType = "KubernetesThanosRulerWithoutGRPCTLS"
		evidence = fmt.Sprintf("Kubernetes ThanosRuler %q exposes its gRPC StoreAPI without a declared TLS configuration", resource.Name)
		recommendation = "为 StoreAPI 配置 grpcServerTlsConfig，并同步配置 Thanos Query 客户端信任；同时使用 NetworkPolicy 限制 gRPC 访问范围。"
	default:
		return model.Finding{}, false
	}
	return model.Finding{ID: model.StableID(analyzerID, resource.ID), Type: findingType, Severity: severity, Category: category, Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name}, Evidence: []string{evidence}, Recommendation: recommendation, Metadata: metadata, Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now}, true
}
