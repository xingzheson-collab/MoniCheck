package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const (
	OTelReceiverPublicUnauthenticatedAnalyzerID = "builtin.otelcol_receiver_public_unauthenticated"
	OTelReceiverPublicPlaintextAnalyzerID       = "builtin.otelcol_receiver_public_plaintext"
)

type OTelReceiverSecurityAnalyzer struct {
	id   string
	name string
}

func NewOTelReceiverPublicUnauthenticatedAnalyzer() *OTelReceiverSecurityAnalyzer {
	return &OTelReceiverSecurityAnalyzer{id: OTelReceiverPublicUnauthenticatedAnalyzerID, name: "OpenTelemetry Collector Receiver Public Without Authentication"}
}

func NewOTelReceiverPublicPlaintextAnalyzer() *OTelReceiverSecurityAnalyzer {
	return &OTelReceiverSecurityAnalyzer{id: OTelReceiverPublicPlaintextAnalyzerID, name: "OpenTelemetry Collector Receiver Public Plaintext"}
}

func (a *OTelReceiverSecurityAnalyzer) ID() string      { return a.id }
func (a *OTelReceiverSecurityAnalyzer) Name() string    { return a.name }
func (a *OTelReceiverSecurityAnalyzer) Version() string { return "0.1.0" }
func (a *OTelReceiverSecurityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver}
}

func (a *OTelReceiverSecurityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	receivers, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeReceiver})
	if err != nil {
		return nil, err
	}
	usedByPipeline := activeOTelPipelineComponents(analysis)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, receiver := range receivers {
		if receiver.Source.System != "otelcol" ||
			receiver.Status != model.ResourceStatusActive ||
			receiver.Metadata[model.MetadataOTelReceiverNetworkSafety] != "true" ||
			!usedByPipeline[receiver.ID] {
			continue
		}
		if finding, ok := a.finding(receiver, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func (a *OTelReceiverSecurityAnalyzer) finding(receiver model.Resource, now time.Time) (model.Finding, bool) {
	count := 0
	findingType := ""
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}
	switch a.id {
	case OTelReceiverPublicUnauthenticatedAnalyzerID:
		count = otelReceiverPositiveMetadataInt(receiver.Metadata[model.MetadataOTelReceiverPublicUnauthenticatedCnt])
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "OTelReceiverPublicUnauthenticated"
		evidence = fmt.Sprintf("OpenTelemetry Collector receiver %q exposes %d explicitly public OTLP endpoint(s) without a configured authenticator", receiver.Name, count)
		recommendation = "将 OTLP receiver 绑定到受控内部地址，或为每个公网 protocol 配置认证扩展，并通过网络策略、入口代理和租户授权限制遥测写入。"
		metadata["public_unauthenticated_count"] = strconv.Itoa(count)
	case OTelReceiverPublicPlaintextAnalyzerID:
		count = otelReceiverPositiveMetadataInt(receiver.Metadata[model.MetadataOTelReceiverPublicPlaintextCount])
		if count == 0 {
			return model.Finding{}, false
		}
		findingType = "OTelReceiverPublicPlaintext"
		evidence = fmt.Sprintf("OpenTelemetry Collector receiver %q exposes %d explicitly public OTLP endpoint(s) without a complete TLS certificate and key declaration", receiver.Name, count)
		recommendation = "将 OTLP receiver 绑定到受控内部地址，或为每个公网 protocol 配置完整 TLS 证书与私钥，并验证客户端信任和必要的双向 TLS。"
		metadata["public_plaintext_count"] = strconv.Itoa(count)
	default:
		return model.Finding{}, false
	}
	return model.Finding{
		ID:             model.StableID(a.id, receiver.ID),
		Type:           findingType,
		Severity:       model.SeverityCritical,
		Category:       model.FindingCategorySecurity,
		Resource:       model.ResourceRef{ID: receiver.ID, Type: receiver.Type, Name: receiver.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func otelReceiverPositiveMetadataInt(raw string) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}
