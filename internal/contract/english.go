package contract

import (
	"fmt"
	"strings"
	"unicode"

	"monicheck/internal/model"
)

var englishFindingRecommendations = map[string]string{
	"AlertRuleMetricNotCollected":    "Restore collection for the bound metric or correct the alert expression, then prove the rule evaluates against current data and send a controlled notification test.",
	"AlertWithoutGeneratorURL":       "Configure a valid external or generator URL for the alert producer so responders can open the originating query or rule context, then verify a newly emitted alert contains the link.",
	"BrokenTarget":                   "Check exporter health, network reachability, and the effective Prometheus scrape configuration; rerun discovery after the target recovers.",
	"HighCardinalityMetric":          "Review label value growth and downstream consumers. Remove unbounded labels or narrow collection only after dependency validation.",
	"MissingMetricUnit":              "Declare the metric unit in metadata or use an unambiguous unit suffix so queries, dashboards, and alerts preserve the intended meaning.",
	"MissingMonitoringCoverage":      "Add the missing signal coverage or register a scoped, time-bound exception with an accountable owner.",
	"PanelMetricNotCollected":        "Restore collection for the explicitly bound metric or update the panel query after owner review, then rerun the audit and load the panel against the same datasource.",
	"RecordingRuleInputNotCollected": "Restore the bound input metric or correct the recording rule expression, then verify the output series and every dependent alert.",
	"MissingAlertDuration":           "Set a non-zero alert hold duration appropriate to the symptom and evaluation interval, then test that transient noise does not page responders.",
	"MissingOwner":                   "Add a stable owner or team label so findings, lifecycle decisions, and remediation can be routed to an accountable group.",
	"MissingRuleQuery":               "Add or repair the alert or recording rule query, validate it against current data, and confirm the rule evaluates successfully before enabling notifications.",
	"MissingRunbook":                 "Add a valid runbook URL with diagnosis, impact, mitigation, and escalation steps, then verify responders can open it from the emitted alert.",
	"NoAnnotation":                   "Add concise summary and description annotations that explain the symptom, impact, and first diagnostic step, then inspect a rendered alert notification.",
	"OrphanAlert":                    "Restore the rule's metric dependency or remove the obsolete alert after confirming no dashboard, SLO, notification, or response workflow still relies on it.",
	"UnallocatedMetricCost":          "Add one stable team or owner attribution value so measured active series can be assigned to an accountable cost boundary.",
	"AmbiguousMetricCostAllocation":  "Resolve conflicting ownership labels or metadata and retain one stable attribution value before using the series in cost reporting.",
	"UnusedMetric":                   "Confirm the metric has no dashboard, alert, recording-rule, or external consumer before disabling collection or marking it deprecated.",
}

// PresentationRecommendation localizes only built-in product findings. User
// authored Rule Engine and external findings retain their original language.
func PresentationRecommendation(finding model.Finding) string {
	current := strings.TrimSpace(finding.Recommendation)
	if !isBuiltInPresentationFinding(finding) {
		return current
	}
	if current == "" || containsHan(current) {
		return EnglishRecommendation(finding)
	}
	return current
}

// PresentationEvidence applies the same boundary to report projections and
// protects legacy built-in findings created before normalization was added.
func PresentationEvidence(finding model.Finding) []string {
	if isBuiltInPresentationFinding(finding) && evidenceContainsHan(finding.Evidence) {
		return EnglishEvidence(finding)
	}
	return append([]string(nil), finding.Evidence...)
}

// EnglishRecommendation guarantees an English product fallback for built-in
// findings while preserving already-English and user-authored recommendations.
func EnglishRecommendation(finding model.Finding) string {
	current := strings.TrimSpace(finding.Recommendation)
	if current != "" && !containsHan(current) {
		return current
	}
	if recommendation := englishFindingRecommendations[finding.Type]; recommendation != "" {
		return recommendation
	}
	resource := string(finding.Resource.Type)
	if resource == "" {
		resource = "resource"
	}
	domain := strings.ToLower(finding.Type + " " + resource)
	switch {
	case strings.Contains(domain, "kubernetes"):
		return "Correct the Kubernetes manifest or Operator-managed workload condition described by the evidence, verify reconciliation and runtime coverage, then rerun discovery."
	case strings.Contains(domain, "otel") || strings.Contains(domain, "opentelemetry") || strings.Contains(domain, "telemetryconnector"):
		return "Correct the OpenTelemetry Collector component, pipeline, or runtime condition described by the evidence, reload the Collector, and verify telemetry flow before resolving the finding."
	case strings.Contains(domain, "prometheus") || strings.Contains(domain, "thanos") || strings.Contains(domain, "mimir") || strings.Contains(domain, "cortex") || strings.Contains(domain, "victoriametrics"):
		return "Correct the Prometheus-compatible runtime, scrape, storage, or rule condition described by the evidence, reload safely, and verify targets, rules, and queries."
	case strings.Contains(domain, "grafana") || strings.Contains(domain, "dashboard") || strings.Contains(domain, "panel") || strings.Contains(domain, "datasource"):
		return "Correct the dashboard, datasource, or Grafana alerting condition described by the evidence, validate dependent queries and notifications, then rerun discovery."
	case strings.Contains(domain, "alertmanager") || strings.Contains(domain, "receiver") || strings.Contains(domain, "notification") || strings.Contains(domain, "inhibition"):
		return "Correct the alert routing or delivery condition described by the evidence, send a controlled notification test, and verify recovery delivery before resolving the finding."
	case strings.Contains(domain, "loki") || strings.Contains(domain, "logstream") || strings.Contains(domain, "logquery"):
		return "Correct the log collection, label, or query condition described by the evidence, then verify bounded query scope and successful ingestion."
	case strings.Contains(domain, "tempo") || strings.Contains(domain, "jaeger") || strings.Contains(domain, "trace") || strings.Contains(domain, "pyroscope"):
		return "Correct the trace or profile collection condition described by the evidence, then verify service discovery, ingestion, and a representative query."
	case strings.Contains(domain, "opensearch") || strings.Contains(domain, "elasticsearch"):
		return "Correct the search-cluster capacity, security, or lifecycle condition described by the evidence, then verify cluster health and representative queries."
	case strings.Contains(domain, "datadog") || strings.Contains(domain, "newrelic") || strings.Contains(domain, "skywalking"):
		return "Correct the provider monitor, notification, or telemetry condition described by the evidence, then verify the provider reports a healthy evaluated state."
	}
	switch finding.Category {
	case model.FindingCategoryCost:
		return fmt.Sprintf("Review measured usage and downstream consumers for this %s. Reduce unused telemetry, cardinality, or query cost only after dependency validation.", resource)
	case model.FindingCategoryReliability:
		return fmt.Sprintf("Restore and verify the affected scrape, alerting, query, or dependency path for this %s before resolving the finding.", resource)
	case model.FindingCategorySecurity:
		return fmt.Sprintf("Remove the insecure configuration from this %s, rotate affected credentials when applicable, and verify the protected path again.", resource)
	case model.FindingCategoryConfiguration:
		return fmt.Sprintf("Align this %s with the effective platform configuration and rerun discovery to verify the corrected state.", resource)
	case model.FindingCategoryLifecycle:
		return fmt.Sprintf("Confirm whether this %s is still required, review downstream impact, then deprecate or remove it through the normal change process.", resource)
	default:
		return fmt.Sprintf("Review the evidence for this %s, apply the relevant naming, metadata, query, or ownership correction, and rerun analysis.", resource)
	}
}

// EnglishEvidence keeps already-English evidence intact and replaces only
// untranslated built-in text with a deterministic, privacy-equivalent summary.
func EnglishEvidence(finding model.Finding) []string {
	result := make([]string, 0, len(finding.Evidence))
	fallbackAdded := false
	for _, evidence := range finding.Evidence {
		evidence = strings.TrimSpace(evidence)
		if evidence == "" {
			continue
		}
		if !containsHan(evidence) {
			result = append(result, evidence)
			continue
		}
		if fallbackAdded {
			continue
		}
		resource := string(finding.Resource.Type)
		if resource == "" {
			resource = "resource"
		}
		findingType := strings.TrimSpace(finding.Type)
		if findingType == "" {
			findingType = "governance"
		}
		result = append(result, fmt.Sprintf("This %s matched the built-in %s check; review its normalized metadata and source configuration.", resource, findingType))
		fallbackAdded = true
	}
	return result
}

func evidenceContainsHan(evidence []string) bool {
	for _, item := range evidence {
		if containsHan(item) {
			return true
		}
	}
	return false
}

func isBuiltInPresentationFinding(finding model.Finding) bool {
	analyzerID := strings.TrimSpace(finding.Metadata["analyzer_id"])
	return strings.HasPrefix(analyzerID, "builtin.") && analyzerID != "builtin.rule_engine"
}

func containsHan(value string) bool {
	for _, character := range value {
		if unicode.Is(unicode.Han, character) {
			return true
		}
	}
	return false
}
