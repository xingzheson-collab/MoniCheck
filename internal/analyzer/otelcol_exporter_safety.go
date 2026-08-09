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
	OTelExporterSendingQueueDisabledAnalyzerID = "builtin.otelcol_exporter_sending_queue_disabled"
	OTelExporterRetryDisabledAnalyzerID        = "builtin.otelcol_exporter_retry_disabled"
	OTelExporterInsecureTLSAnalyzerID          = "builtin.otelcol_exporter_insecure_tls"
)

type OTelExporterSafetyAnalyzer struct {
	id   string
	name string
}

func NewOTelExporterSendingQueueDisabledAnalyzer() *OTelExporterSafetyAnalyzer {
	return &OTelExporterSafetyAnalyzer{id: OTelExporterSendingQueueDisabledAnalyzerID, name: "OpenTelemetry Collector Exporter Sending Queue Disabled"}
}

func NewOTelExporterRetryDisabledAnalyzer() *OTelExporterSafetyAnalyzer {
	return &OTelExporterSafetyAnalyzer{id: OTelExporterRetryDisabledAnalyzerID, name: "OpenTelemetry Collector Exporter Retry Disabled"}
}

func NewOTelExporterInsecureTLSAnalyzer() *OTelExporterSafetyAnalyzer {
	return &OTelExporterSafetyAnalyzer{id: OTelExporterInsecureTLSAnalyzerID, name: "OpenTelemetry Collector Exporter Insecure TLS"}
}

func (a *OTelExporterSafetyAnalyzer) ID() string      { return a.id }
func (a *OTelExporterSafetyAnalyzer) Name() string    { return a.name }
func (a *OTelExporterSafetyAnalyzer) Version() string { return "0.1.0" }
func (a *OTelExporterSafetyAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExporter}
}

func (a *OTelExporterSafetyAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	exporters, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeExporter})
	if err != nil {
		return nil, err
	}
	usedByPipeline := activeOTelPipelineComponents(analysis)
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, exporter := range exporters {
		if !isActiveOTelComponent(exporter) || !usedByPipeline[exporter.ID] {
			continue
		}
		if finding, ok := a.finding(exporter, now); ok {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}

func (a *OTelExporterSafetyAnalyzer) finding(exporter model.Resource, now time.Time) (model.Finding, bool) {
	findingType := ""
	severity := model.SeverityWarning
	category := model.FindingCategoryReliability
	evidence := ""
	recommendation := ""
	metadata := map[string]string{"analyzer_id": a.id}
	switch a.id {
	case OTelExporterSendingQueueDisabledAnalyzerID:
		if exporter.Metadata[model.MetadataOTelExporterSendingQueueEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelExporterSendingQueueDisabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector exporter %q is used by an active pipeline and explicitly disables its sending queue", exporter.Name)
		recommendation = "启用 exporter sending_queue，并按流量、后端延迟和可用内存设置队列容量与消费者数量；同时监控队列大小、入队失败和导出失败。"
		metadata["sending_queue_enabled"] = "false"
	case OTelExporterRetryDisabledAnalyzerID:
		if exporter.Metadata[model.MetadataOTelExporterRetryOnFailureEnabled] != "false" {
			return model.Finding{}, false
		}
		findingType = "OTelExporterRetryDisabled"
		evidence = fmt.Sprintf("OpenTelemetry Collector exporter %q is used by an active pipeline and explicitly disables retry_on_failure", exporter.Name)
		recommendation = "启用 retry_on_failure，并根据后端恢复时间设置受限的初始间隔、最大间隔和最长重试时间；结合 sending_queue 避免短暂故障直接丢失遥测数据。"
		metadata["retry_on_failure_enabled"] = "false"
	case OTelExporterInsecureTLSAnalyzerID:
		insecure := exporter.Metadata[model.MetadataOTelExporterTLSInsecure] == "true"
		skipVerify := exporter.Metadata[model.MetadataOTelExporterTLSInsecureSkipVerify] == "true"
		if !insecure && !skipVerify {
			return model.Finding{}, false
		}
		findingType = "OTelExporterInsecureTLS"
		severity = model.SeverityCritical
		category = model.FindingCategorySecurity
		switch {
		case insecure && skipVerify:
			evidence = fmt.Sprintf("OpenTelemetry Collector exporter %q explicitly enables insecure transport and disables TLS certificate verification", exporter.Name)
		case insecure:
			evidence = fmt.Sprintf("OpenTelemetry Collector exporter %q explicitly enables insecure transport", exporter.Name)
		default:
			evidence = fmt.Sprintf("OpenTelemetry Collector exporter %q explicitly disables TLS certificate verification", exporter.Name)
		}
		recommendation = "为 exporter 启用经过身份验证的 TLS，关闭 insecure 和 insecure_skip_verify，并通过受信任 CA 或证书固定校验后端身份。"
		metadata["tls_insecure"] = fmt.Sprintf("%t", insecure)
		metadata["tls_insecure_skip_verify"] = fmt.Sprintf("%t", skipVerify)
	default:
		return model.Finding{}, false
	}
	return model.Finding{
		ID:             model.StableID(a.id, exporter.ID),
		Type:           findingType,
		Severity:       severity,
		Category:       category,
		Resource:       model.ResourceRef{ID: exporter.ID, Type: exporter.Type, Name: exporter.Name},
		Evidence:       []string{evidence},
		Recommendation: recommendation,
		Metadata:       metadata,
		Status:         model.FindingStatusOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, true
}

func activeOTelPipelineComponents(analysis Context) map[string]bool {
	used := map[string]bool{}
	if analysis.Graph == nil {
		return used
	}
	for _, resource := range analysis.Graph.Resources() {
		if !isActiveOTelPipeline(resource) {
			continue
		}
		for _, relationship := range analysis.Graph.Outgoing(resource.ID) {
			if relationship.Type == model.RelationshipUses {
				used[relationship.ToID] = true
			}
		}
	}
	return used
}
