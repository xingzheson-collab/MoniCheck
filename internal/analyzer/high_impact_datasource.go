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
	HighImpactDatasourceAnalyzerID               = "builtin.high_impact_datasource"
	defaultHighImpactDatasourceConsumerThreshold = 5
)

type HighImpactDatasourceAnalyzer struct{}

func NewHighImpactDatasourceAnalyzer() *HighImpactDatasourceAnalyzer {
	return &HighImpactDatasourceAnalyzer{}
}

func (a *HighImpactDatasourceAnalyzer) ID() string {
	return HighImpactDatasourceAnalyzerID
}

func (a *HighImpactDatasourceAnalyzer) Name() string {
	return "High Impact Datasource"
}

func (a *HighImpactDatasourceAnalyzer) Version() string {
	return "0.1.0"
}

func (a *HighImpactDatasourceAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypeDatasource}
}

func (a *HighImpactDatasourceAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	datasources, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: model.ResourceTypeDatasource})
	if err != nil {
		return nil, err
	}
	if analysis.Graph == nil {
		return nil, nil
	}

	threshold := intConfig(analysis.Config, "high_impact_datasource_consumer_threshold", defaultHighImpactDatasourceConsumerThreshold)
	findings := make([]model.Finding, 0)
	now := time.Now().UTC()
	for _, datasource := range datasources {
		if datasource.Status != model.ResourceStatusActive {
			continue
		}
		consumers := datasourceConsumers(datasource.ID, analysis)
		if len(consumers) <= threshold {
			continue
		}

		consumerNames := sampledConsumerNames(consumers, defaultHighImpactMetricConsumerNameSample)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), datasource.ID),
			Type:     "HighImpactDatasource",
			Severity: model.SeverityInfo,
			Resource: model.ResourceRef{
				ID:   datasource.ID,
				Type: datasource.Type,
				Name: datasource.Name,
			},
			Evidence: []string{
				fmt.Sprintf("datasource %q has %d downstream consumers, threshold is %d", datasource.Name, len(consumers), threshold),
				fmt.Sprintf("sample consumers: %s", strings.Join(consumerNames, ", ")),
			},
			Recommendation: "将该 Datasource 纳入变更保护清单；修改 URL、鉴权、默认状态或代理模式前先评估 Dashboard、Panel 和 Alert 的影响面。",
			Metadata: map[string]string{
				"analyzer_id":    a.ID(),
				"consumer_count": strconv.Itoa(len(consumers)),
				"threshold":      strconv.Itoa(threshold),
				"consumers":      strings.Join(consumerNames, ","),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func datasourceConsumers(datasourceID string, analysis Context) []model.Resource {
	seen := make(map[string]bool)
	consumers := make([]model.Resource, 0)
	for _, relationship := range analysis.Graph.Incoming(datasourceID) {
		if relationship.Type != model.RelationshipUses || seen[relationship.FromID] {
			continue
		}
		consumer, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || consumer.Status != model.ResourceStatusActive {
			continue
		}
		if !isDatasourceConsumerResource(consumer.Type) {
			continue
		}
		seen[consumer.ID] = true
		consumers = append(consumers, consumer)
	}
	sortResourcesByTypeAndName(consumers)
	return consumers
}

func isDatasourceConsumerResource(resourceType model.ResourceType) bool {
	switch resourceType {
	case model.ResourceTypeDashboard, model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule, model.ResourceTypeTSDB:
		return true
	default:
		return false
	}
}

func sortResourcesByTypeAndName(resources []model.Resource) {
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Type == resources[j].Type {
			return resources[i].Name < resources[j].Name
		}
		return resources[i].Type < resources[j].Type
	})
}
