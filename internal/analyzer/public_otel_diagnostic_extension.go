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

const PublicOTelDiagnosticExtensionAnalyzerID = "builtin.public_otel_diagnostic_extension"

type PublicOTelDiagnosticExtensionAnalyzer struct{}

func NewPublicOTelDiagnosticExtensionAnalyzer() *PublicOTelDiagnosticExtensionAnalyzer {
	return &PublicOTelDiagnosticExtensionAnalyzer{}
}

func (a *PublicOTelDiagnosticExtensionAnalyzer) ID() string {
	return PublicOTelDiagnosticExtensionAnalyzerID
}

func (a *PublicOTelDiagnosticExtensionAnalyzer) Name() string {
	return "Public OpenTelemetry Diagnostic Extension"
}

func (a *PublicOTelDiagnosticExtensionAnalyzer) Version() string {
	return "0.1.0"
}

func (a *PublicOTelDiagnosticExtensionAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeExtension}
}

func (a *PublicOTelDiagnosticExtensionAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	extensions, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeExtension})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, extension := range extensions {
		extensionType := strings.TrimSpace(extension.Metadata[model.MetadataComponentType])
		if extension.Source.System != "otelcol" ||
			extension.Status != model.ResourceStatusActive ||
			extension.Metadata[model.MetadataOTelExtensionEnabled] != "true" ||
			extension.Metadata[model.MetadataOTelEndpointExposureEvaluable] != "true" ||
			extension.Metadata[model.MetadataOTelEndpointPublic] != "true" ||
			(extensionType != "pprof" && extensionType != "zpages") {
			continue
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), extension.ID),
			Type:     "PublicOTelDiagnosticExtension",
			Severity: model.SeverityWarning,
			Category: model.FindingCategorySecurity,
			Resource: model.ResourceRef{ID: extension.ID, Type: extension.Type, Name: extension.Name},
			Evidence: []string{
				fmt.Sprintf("Enabled OpenTelemetry Collector %s extension explicitly binds its diagnostic endpoint to all network interfaces", extensionType),
			},
			Recommendation: "将诊断扩展绑定到 loopback 或受控管理地址，并通过网络策略、认证代理或临时端口转发限制访问；不要把 profiling 或 zPages 调试信息直接暴露到非受信网络。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"extension_type": extensionType,
				"public_bind":    "true",
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Resource.Name < findings[j].Resource.Name
	})
	return findings, nil
}
