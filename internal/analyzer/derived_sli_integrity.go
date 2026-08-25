package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

const DerivedSLIIntegrityAnalyzerID = "builtin.derived_sli_integrity"

type DerivedSLIIntegrityAnalyzer struct{}

func NewDerivedSLIIntegrityAnalyzer() *DerivedSLIIntegrityAnalyzer {
	return &DerivedSLIIntegrityAnalyzer{}
}

func (a *DerivedSLIIntegrityAnalyzer) ID() string      { return DerivedSLIIntegrityAnalyzerID }
func (a *DerivedSLIIntegrityAnalyzer) Name() string    { return "Derived SLI Integrity" }
func (a *DerivedSLIIntegrityAnalyzer) Version() string { return "0.1.0" }
func (a *DerivedSLIIntegrityAnalyzer) InputTypes() []model.ResourceType {
	return []model.ResourceType{model.ResourceTypePanel, model.ResourceTypeAlertRule, model.ResourceTypeRecordingRule}
}

func (a *DerivedSLIIntegrityAnalyzer) Execute(ctx context.Context, analysis Context) ([]model.Finding, error) {
	var resources []model.Resource
	for _, resourceType := range a.InputTypes() {
		items, err := analysis.Resources.List(ctx, storage.ResourceFilter{Type: resourceType})
		if err != nil {
			return nil, err
		}
		resources = append(resources, items...)
	}

	now := time.Now().UTC()
	findings := make([]model.Finding, 0)
	for _, resource := range resources {
		if resource.Status != model.ResourceStatusActive || isDisabledAlert(resource) {
			continue
		}
		derived, found, err := connector.ExtractPromQLDerivedSLI(strings.TrimSpace(resource.Metadata[model.MetadataPromQL]))
		if err != nil || !found {
			continue
		}
		findingType, severity, evidence := derivedSLIEvidence(resource, derived, analysis)
		if findingType == "" {
			continue
		}
		findings = append(findings, model.Finding{
			ID: model.StableID(a.ID(), findingType, resource.ID), Type: findingType,
			Severity: severity, Category: model.FindingCategoryReliability,
			Resource: model.ResourceRef{ID: resource.ID, Type: resource.Type, Name: resource.Name},
			Evidence: evidence, Recommendation: derivedSLIRecommendation(findingType),
			Metadata: map[string]string{
				"analyzer_id": a.ID(), "derived_sli_function": derived.Function,
				"derived_sli_inputs":           strings.Join(derived.InputMetrics, ","),
				"derived_sli_quantiles":        derivedSLIQuantiles(derived.Quantiles),
				"derived_sli_dynamic_quantile": strconv.FormatBool(derived.DynamicQuantile),
			},
			Status: model.FindingStatusOpen, CreatedAt: now, UpdatedAt: now,
		})
	}
	return findings, nil
}

func derivedSLIEvidence(resource model.Resource, derived connector.DerivedSLIExpression, analysis Context) (string, model.Severity, []string) {
	if len(derived.InputMetrics) == 0 {
		return "DerivedSLIWithoutMetricInput", model.SeverityWarning, []string{fmt.Sprintf("%s %q calls histogram_quantile without a statically resolvable metric input", derivedSLIResourceKind(resource), resource.Name)}
	}
	if analysis.Graph == nil {
		return "DerivedSLIInputUnverified", model.SeverityWarning, []string{fmt.Sprintf("%s %q has a derived SLI expression but no resource graph is available to verify its input chain", derivedSLIResourceKind(resource), resource.Name)}
	}

	missing, drifted, unverified := []string{}, []string{}, []string{}
	for _, input := range derived.InputMetrics {
		state := derivedSLIInputEvidence(resource.ID, input, analysis, map[string]bool{})
		switch state {
		case "MISSING":
			missing = append(missing, input)
		case "DRIFTED":
			drifted = append(drifted, input)
		case "UNKNOWN":
			unverified = append(unverified, input)
		}
	}
	if len(missing) > 0 {
		return "DerivedSLIInputNotCollected", model.SeverityCritical, []string{fmt.Sprintf("%s %q depends on derived SLI input(s) absent from an explicitly bound Prometheus inventory: %s", derivedSLIResourceKind(resource), resource.Name, strings.Join(missing, ", "))}
	}
	if len(drifted) > 0 {
		return "DerivedSLIMetricContractDrift", model.SeverityCritical, []string{fmt.Sprintf("%s %q depends on histogram input(s) with conflicting or incompatible metric TYPE evidence: %s", derivedSLIResourceKind(resource), resource.Name, strings.Join(drifted, ", "))}
	}
	if len(unverified) > 0 {
		return "DerivedSLIInputUnverified", model.SeverityWarning, []string{fmt.Sprintf("%s %q has derived SLI input(s) whose collection or recording-rule chain is not proven by current evidence: %s", derivedSLIResourceKind(resource), resource.Name, strings.Join(unverified, ", "))}
	}
	return "", "", nil
}

func derivedSLIInputEvidence(resourceID, inputName string, analysis Context, visited map[string]bool) string {
	matched := false
	for _, relationship := range analysis.Graph.Outgoing(resourceID) {
		if relationship.Type != model.RelationshipUses {
			continue
		}
		if referenceName := strings.TrimSpace(relationship.Metadata[model.MetadataMetricReferenceName]); referenceName != "" && referenceName != inputName {
			continue
		}
		target, ok := analysis.Graph.Resource(relationship.ToID)
		if ok && target.Type == model.ResourceTypeMetric && target.Name != inputName {
			continue
		}
		matched = true
		if !ok {
			if relationship.Metadata[model.MetadataMetricInventoryBinding] == "EXACT" {
				return "MISSING"
			}
			continue
		}
		if derivedSLIMetricContractDrift(target, analysis) {
			return "DRIFTED"
		}
		if derivedSLIMetricObserved(target.ID, analysis, visited) {
			return "OBSERVED"
		}
	}
	if !matched {
		return "UNKNOWN"
	}
	return "UNKNOWN"
}

func derivedSLIMetricObserved(metricID string, analysis Context, visited map[string]bool) bool {
	if visited[metricID] {
		return false
	}
	visited[metricID] = true
	defer delete(visited, metricID)
	for _, relationship := range analysis.Graph.Incoming(metricID) {
		if relationship.Type != model.RelationshipProduces {
			continue
		}
		producer, ok := analysis.Graph.Resource(relationship.FromID)
		if !ok || producer.Status != model.ResourceStatusActive {
			continue
		}
		if producer.Type == model.ResourceTypeTarget {
			return true
		}
		if producer.Type != model.ResourceTypeRecordingRule {
			continue
		}
		inputs := 0
		allObserved := true
		for _, inputRelationship := range analysis.Graph.Outgoing(producer.ID) {
			if inputRelationship.Type != model.RelationshipUses {
				continue
			}
			inputs++
			input, ok := analysis.Graph.Resource(inputRelationship.ToID)
			if !ok || input.Type != model.ResourceTypeMetric || !derivedSLIMetricObserved(input.ID, analysis, visited) {
				allObserved = false
				break
			}
		}
		if inputs > 0 && allObserved {
			return true
		}
	}
	return false
}

func derivedSLIMetricContractDrift(metric model.Resource, analysis Context) bool {
	if len(metricMetadataVariantValues(metric.Metadata[model.MetadataMetricTypeVariants])) > 1 {
		return true
	}
	if !strings.HasSuffix(metric.Name, "_bucket") {
		return false
	}
	baseName := strings.TrimSuffix(metric.Name, "_bucket")
	for _, candidate := range analysis.Graph.Resources() {
		if candidate.Type != model.ResourceTypeMetric || candidate.Name != baseName || candidate.Source.Instance != metric.Source.Instance {
			continue
		}
		if len(metricMetadataVariantValues(candidate.Metadata[model.MetadataMetricTypeVariants])) > 1 {
			return true
		}
		metricType := strings.ToLower(strings.TrimSpace(candidate.Metadata[model.MetadataMetricType]))
		if metricType != "" && metricType != "histogram" {
			return true
		}
	}
	return false
}

func derivedSLIQuantiles(values []float64) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.FormatFloat(value, 'g', -1, 64))
	}
	return strings.Join(parts, ",")
}

func derivedSLIResourceKind(resource model.Resource) string {
	switch resource.Type {
	case model.ResourceTypePanel:
		return "panel"
	case model.ResourceTypeRecordingRule:
		return "recording rule"
	default:
		return "alert rule"
	}
}

func derivedSLIRecommendation(findingType string) string {
	switch findingType {
	case "DerivedSLIInputNotCollected":
		return "Restore the explicitly bound histogram or recording-rule input, then evaluate the P95/P99 query against the same Prometheus inventory and rerun the audit."
	case "DerivedSLIMetricContractDrift":
		return "Standardize the histogram metric TYPE across emitters before trusting the derived percentile, then rerun metadata collection and evaluate the query."
	case "DerivedSLIWithoutMetricInput":
		return "Review the histogram_quantile expression and provide a statically evaluable histogram or recording-rule input; do not close this finding from a metric name alone."
	default:
		return "Verify the histogram input or recording-rule chain in the intended Prometheus datasource; keep the result UNKNOWN until collection evidence is available."
	}
}
