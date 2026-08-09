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
	ServiceObservabilityGapAnalyzerID         = "builtin.service_observability_gap"
	defaultServiceObservabilityMinimumSignals = 2
)

var serviceObservabilitySignalOrder = []string{"metrics", "logs", "dashboards", "alerts", "traces", "profiles"}

type ServiceObservabilityGapAnalyzer struct{}

func NewServiceObservabilityGapAnalyzer() *ServiceObservabilityGapAnalyzer {
	return &ServiceObservabilityGapAnalyzer{}
}

func (a *ServiceObservabilityGapAnalyzer) ID() string {
	return ServiceObservabilityGapAnalyzerID
}

func (a *ServiceObservabilityGapAnalyzer) Name() string {
	return "Service Observability Gap"
}

func (a *ServiceObservabilityGapAnalyzer) Version() string {
	return "0.1.0"
}

func (a *ServiceObservabilityGapAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeService,
		model.ResourceTypeMetric,
		model.ResourceTypeDashboard,
		model.ResourceTypePanel,
		model.ResourceTypeAlert,
		model.ResourceTypeAlertRule,
		model.ResourceTypeLogStream,
		model.ResourceTypeTraceService,
		model.ResourceTypeTraceOperation,
		model.ResourceTypeProfileService,
	}
}

func (a *ServiceObservabilityGapAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.Graph == nil {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	availableSignals := observabilitySignals(resources)
	if len(availableSignals) < 2 {
		return nil, nil
	}
	minimumSignals := intConfig(analysis.Config, "service_observability_minimum_signals", defaultServiceObservabilityMinimumSignals)
	if minimumSignals > len(availableSignals) {
		minimumSignals = len(availableSignals)
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, service := range resources {
		if service.Type != model.ResourceTypeService || service.Status != model.ResourceStatusActive {
			continue
		}
		observedSignals := observabilitySignals(serviceMembers(service.ID, analysis))
		observedSignals = intersectSignals(observedSignals, availableSignals)
		if len(observedSignals) >= minimumSignals {
			continue
		}
		missingSignals := missingObservabilitySignals(availableSignals, observedSignals)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), service.ID),
			Type:     "ServiceObservabilityGap",
			Severity: model.SeverityWarning,
			Resource: model.ResourceRef{ID: service.ID, Type: service.Type, Name: service.Name},
			Evidence: []string{
				fmt.Sprintf("service %q covers %d of %d available observability signals; minimum is %d", service.Name, len(observedSignals), len(availableSignals), minimumSignals),
				fmt.Sprintf("observed signals: %s", signalList(observedSignals)),
				fmt.Sprintf("missing signals: %s", signalList(missingSignals)),
			},
			Recommendation: "为该服务补充缺失的指标、Dashboard、告警或 Trace Operation 关联；优先保证至少两类独立信号，并使用一致的 service/app 标签建立 Service 归属。",
			Metadata: map[string]string{
				"analyzer_id":          a.ID(),
				"available_signals":    strings.Join(availableSignals, ","),
				"observed_signals":     strings.Join(observedSignals, ","),
				"missing_signals":      strings.Join(missingSignals, ","),
				"signal_count":         strconv.Itoa(len(observedSignals)),
				"minimum_signal_count": strconv.Itoa(minimumSignals),
			},
			Status:    model.FindingStatusOpen,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return findings, nil
}

func observabilitySignals(resources []model.Resource) []string {
	signals := make(map[string]bool)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive {
			continue
		}
		signal := observabilitySignal(resource)
		if signal != "" {
			signals[signal] = true
		}
	}
	result := make([]string, 0, len(signals))
	for _, signal := range serviceObservabilitySignalOrder {
		if signals[signal] {
			result = append(result, signal)
		}
	}
	return result
}

func observabilitySignal(resource model.Resource) string {
	switch resource.Type {
	case model.ResourceTypeMetric, model.ResourceTypeRecordingRule, model.ResourceTypeTarget, model.ResourceTypeJob, model.ResourceTypeExporter:
		return "metrics"
	case model.ResourceTypeDashboard, model.ResourceTypePanel:
		return "dashboards"
	case model.ResourceTypeAlert:
		return "alerts"
	case model.ResourceTypeAlertRule:
		if !isDisabledAlert(resource) {
			return "alerts"
		}
	case model.ResourceTypeLogStream:
		return "logs"
	case model.ResourceTypeTraceService, model.ResourceTypeTraceOperation:
		return "traces"
	case model.ResourceTypeProfileService:
		return "profiles"
	}
	return ""
}

func intersectSignals(signals []string, available []string) []string {
	allowed := make(map[string]bool, len(available))
	for _, signal := range available {
		allowed[signal] = true
	}
	result := make([]string, 0, len(signals))
	for _, signal := range signals {
		if allowed[signal] {
			result = append(result, signal)
		}
	}
	return result
}

func missingObservabilitySignals(available []string, observed []string) []string {
	present := make(map[string]bool, len(observed))
	for _, signal := range observed {
		present[signal] = true
	}
	missing := make([]string, 0, len(available))
	for _, signal := range available {
		if !present[signal] {
			missing = append(missing, signal)
		}
	}
	return missing
}

func signalList(signals []string) string {
	if len(signals) == 0 {
		return "none"
	}
	values := append([]string(nil), signals...)
	sort.Strings(values)
	return strings.Join(values, ", ")
}
