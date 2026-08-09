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

const OTelColOneSidedConnectorAnalyzerID = "builtin.otelcol_one_sided_connector"

type OTelColOneSidedConnectorAnalyzer struct{}

func NewOTelColOneSidedConnectorAnalyzer() *OTelColOneSidedConnectorAnalyzer {
	return &OTelColOneSidedConnectorAnalyzer{}
}

func (a *OTelColOneSidedConnectorAnalyzer) ID() string {
	return OTelColOneSidedConnectorAnalyzerID
}

func (a *OTelColOneSidedConnectorAnalyzer) Name() string {
	return "One-Sided OpenTelemetry Collector Connector"
}

func (a *OTelColOneSidedConnectorAnalyzer) Version() string {
	return "0.1.0"
}

func (a *OTelColOneSidedConnectorAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeTelemetryConnector}
}

func (a *OTelColOneSidedConnectorAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	connectors, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeTelemetryConnector})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, connector := range connectors {
		if connector.Source.System != "otelcol" || connector.Status != model.ResourceStatusActive {
			continue
		}
		receiverUsage, receiverOK := parseNonNegativeCount(connector.Metadata[model.MetadataOTelConnectorReceiverUsage])
		exporterUsage, exporterOK := parseNonNegativeCount(connector.Metadata[model.MetadataOTelConnectorExporterUsage])
		if !receiverOK || !exporterOK || receiverUsage+exporterUsage == 0 ||
			(receiverUsage > 0 && exporterUsage > 0) {
			continue
		}
		missingRole := "receiver"
		if receiverUsage > 0 {
			missingRole = "exporter"
		}
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), connector.ID, missingRole),
			Type:     "OTelConnectorOneSided",
			Severity: model.SeverityCritical,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{
				ID:   connector.ID,
				Type: connector.Type,
				Name: connector.Name,
			},
			Evidence: []string{
				fmt.Sprintf("OpenTelemetry Collector connector %q is referenced by %d receiver pipeline(s) and %d exporter pipeline(s), leaving its %s side disconnected", connector.Name, receiverUsage, exporterUsage, missingRole),
			},
			Recommendation: "将 connector 同时配置为上游 pipeline 的 exporter 和下游 pipeline 的 receiver；如果不再需要跨 pipeline 传递或转换遥测数据，请移除该 connector 及其残留引用。",
			Metadata: map[string]string{
				"analyzer_id":          a.ID(),
				"missing_role":         missingRole,
				"receiver_usage_count": strconv.Itoa(receiverUsage),
				"exporter_usage_count": strconv.Itoa(exporterUsage),
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

func parseNonNegativeCount(value string) (int, bool) {
	count, err := strconv.Atoi(strings.TrimSpace(value))
	return count, err == nil && count >= 0
}
