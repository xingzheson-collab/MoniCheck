package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	coveragepkg "monicheck/internal/coverage"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const MonitoringCoverageExpectationAnalyzerID = "builtin.monitoring_coverage_expectation"

type MonitoringCoverageExpectationAnalyzer struct{}

func NewMonitoringCoverageExpectationAnalyzer() *MonitoringCoverageExpectationAnalyzer {
	return &MonitoringCoverageExpectationAnalyzer{}
}

func (a *MonitoringCoverageExpectationAnalyzer) ID() string {
	return MonitoringCoverageExpectationAnalyzerID
}

func (a *MonitoringCoverageExpectationAnalyzer) Name() string {
	return "Monitoring Coverage Expectation"
}

func (a *MonitoringCoverageExpectationAnalyzer) Version() string {
	return "0.1.0"
}

func (a *MonitoringCoverageExpectationAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{
		model.ResourceTypeService,
		model.ResourceTypeMetric,
		model.ResourceTypeRecordingRule,
		model.ResourceTypeTarget,
		model.ResourceTypeJob,
		model.ResourceTypeExporter,
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

func (a *MonitoringCoverageExpectationAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	if analysis.CoverageExpectations == nil || analysis.CoverageExceptions == nil {
		return nil, nil
	}
	resources, err := analysis.Resources.List(ctx, storage.ResourceFilter{})
	if err != nil {
		return nil, err
	}
	expectations, err := analysis.CoverageExpectations.List(ctx)
	if err != nil {
		return nil, err
	}
	exceptions, err := analysis.CoverageExceptions.List(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	summary := coveragepkg.Assess(resources, analysis.Graph, expectations, exceptions, now)
	findings := make([]model.Finding, 0)
	for _, assessment := range summary.Assessments {
		if assessment.MissingCount == 0 {
			continue
		}
		missing := assessmentSignals(assessment.Signals, coveragepkg.SignalMissing)
		unknown := assessmentSignals(assessment.Signals, coveragepkg.SignalUnknown)
		findings = append(findings, model.Finding{
			ID:       model.StableID(a.ID(), assessment.ExpectationID, assessment.ServiceID),
			Type:     "MissingMonitoringCoverage",
			Severity: model.SeverityWarning,
			Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: assessment.ServiceID, Type: model.ResourceTypeService, Name: assessment.ServiceName},
			Evidence: []string{
				fmt.Sprintf("service %q is missing required monitoring coverage: %s", assessment.ServiceName, strings.Join(missing, ", ")),
				fmt.Sprintf("expectation %q evaluates %d signal(s); %d remain unknown", assessment.ExpectationName, assessment.EvaluableCount, assessment.UnknownCount),
			},
			Recommendation: "Add the missing signal coverage or register a scoped, time-bound coverage exception with an accountable owner.",
			Metadata: map[string]string{
				"analyzer_id":     a.ID(),
				"expectation_id":  assessment.ExpectationID,
				"coverage_state":  string(assessment.State),
				"missing_signals": strings.Join(missing, ","),
				"unknown_signals": strings.Join(unknown, ","),
				"missing_count":   strconv.Itoa(assessment.MissingCount),
				"unknown_count":   strconv.Itoa(assessment.UnknownCount),
				"evaluable_count": strconv.Itoa(assessment.EvaluableCount),
				"observed_count":  strconv.Itoa(assessment.ObservedCount),
				"exempt_count":    strconv.Itoa(assessment.ExemptCount),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func assessmentSignals(items []coveragepkg.SignalAssessment, state coveragepkg.SignalState) []string {
	result := []string{}
	for _, item := range items {
		if item.State == state {
			result = append(result, string(item.Signal))
		}
	}
	return result
}
