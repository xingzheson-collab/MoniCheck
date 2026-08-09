package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const InsecureReceiverEndpointAnalyzerID = "builtin.insecure_receiver_endpoint"

type InsecureReceiverEndpointAnalyzer struct{}

func NewInsecureReceiverEndpointAnalyzer() *InsecureReceiverEndpointAnalyzer {
	return &InsecureReceiverEndpointAnalyzer{}
}
func (a *InsecureReceiverEndpointAnalyzer) ID() string      { return InsecureReceiverEndpointAnalyzerID }
func (a *InsecureReceiverEndpointAnalyzer) Name() string    { return "Insecure Receiver Endpoint" }
func (a *InsecureReceiverEndpointAnalyzer) Version() string { return "0.1.0" }
func (a *InsecureReceiverEndpointAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeReceiver}
}

func (a *InsecureReceiverEndpointAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeReceiver})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		count := notificationPolicyMetadataInt(resource, model.MetadataReceiverInsecureEndpointCount)
		if resource.Status != model.ResourceStatusActive || (resource.Source.System != "alertmanager" && resource.Source.System != "grafana") || resource.Metadata["declared"] != "true" || count == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), resource.ID), Type: "InsecureReceiverEndpoint", Severity: model.SeverityCritical,
			Resource:       model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence:       []string{fmt.Sprintf("receiver contains %d notification endpoint(s) using unencrypted HTTP", count)},
			Recommendation: "将 webhook/API endpoint 切换为 HTTPS，并校验证书与目标身份；不要通过明文 HTTP 发送告警内容或认证信息。",
			Metadata:       map[string]string{"analyzer_id": a.ID(), "insecure_endpoint_count": strconv.Itoa(count)},
			Status:         model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}
