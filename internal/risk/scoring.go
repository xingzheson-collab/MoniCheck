package risk

import "monicheck/internal/model"

const Version = "risk.v1"

func ScoreFinding(finding model.Finding) model.Finding {
	score := Score(finding)
	finding.RiskScore = &score
	return finding
}

func Score(finding model.Finding) model.FindingRiskScore {
	severityValue, severityExplanation := severityWeight(finding.Severity)
	categoryValue, categoryExplanation := categoryWeight(finding.Category)
	exposureValue, exposureExplanation := exposureWeight(finding.Resource.Type)
	components := []model.FindingRiskComponent{
		{Key: "severity", Label: "Severity", Value: severityValue, Maximum: 65, Explanation: severityExplanation},
		{Key: "category", Label: "Governance domain", Value: categoryValue, Maximum: 20, Explanation: categoryExplanation},
		{Key: "exposure", Label: "Resource exposure", Value: exposureValue, Maximum: 15, Explanation: exposureExplanation},
	}
	score := severityValue + categoryValue + exposureValue

	provenance := 0
	provenanceExplanation := "Analyzer provenance is unavailable."
	if finding.Metadata["analyzer_id"] != "" {
		provenance = 40
		provenanceExplanation = "A source Analyzer identifies the deterministic check."
	}
	evidence := 0
	evidenceExplanation := "No normalized evidence is attached."
	if len(finding.Evidence) > 0 {
		evidence = 35
		evidenceExplanation = "Normalized Analyzer evidence is present."
	}
	resource := 0
	resourceExplanation := "The affected resource reference is incomplete."
	if finding.Resource.ID != "" && finding.Resource.Type != "" {
		resource = 25
		resourceExplanation = "The affected resource has a stable identity and type."
	}
	confidenceComponents := []model.FindingRiskComponent{
		{Key: "provenance", Label: "Analyzer provenance", Value: provenance, Maximum: 40, Explanation: provenanceExplanation},
		{Key: "evidence", Label: "Evidence availability", Value: evidence, Maximum: 35, Explanation: evidenceExplanation},
		{Key: "resource", Label: "Resource identity", Value: resource, Maximum: 25, Explanation: resourceExplanation},
	}
	confidence := provenance + evidence + resource

	return model.FindingRiskScore{
		Version:              Version,
		Score:                score,
		Level:                level(score),
		Confidence:           confidence,
		ConfidenceLevel:      confidenceLevel(confidence),
		Components:           components,
		ConfidenceComponents: confidenceComponents,
	}
}

func severityWeight(severity model.Severity) (int, string) {
	switch severity {
	case model.SeverityCritical:
		return 65, "Critical Findings receive the maximum severity contribution."
	case model.SeverityWarning:
		return 40, "Warning Findings receive a material severity contribution."
	case model.SeverityInfo:
		return 20, "Informational Findings receive the baseline severity contribution."
	default:
		return 0, "Unknown severity contributes no severity weight."
	}
}

func categoryWeight(category model.FindingCategory) (int, string) {
	switch category {
	case model.FindingCategorySecurity, model.FindingCategoryReliability:
		return 20, "Security and reliability Findings have direct operational impact."
	case model.FindingCategoryCost:
		return 15, "Cost Findings can create measurable ongoing spend."
	case model.FindingCategoryLifecycle:
		return 10, "Lifecycle Findings represent retained operational debt."
	case model.FindingCategoryConfiguration, model.FindingCategoryQuality:
		return 5, "Configuration and quality Findings receive the baseline domain weight."
	default:
		return 0, "Unknown governance domains contribute no domain weight."
	}
}

func exposureWeight(resourceType model.ResourceType) (int, string) {
	switch resourceType {
	case model.ResourceTypeService:
		return 15, "Service-level Findings can affect an end-to-end operational boundary."
	case model.ResourceTypeInstance, model.ResourceTypeTarget, model.ResourceTypeAlertRule, model.ResourceTypeNotificationPolicy:
		return 12, "Runtime and alert-delivery resources have broad operational exposure."
	case model.ResourceTypeMetric, model.ResourceTypeRecordingRule, model.ResourceTypeDatasource:
		return 10, "Shared telemetry and datasource resources have reusable downstream exposure."
	case model.ResourceTypeDashboard, model.ResourceTypePanel:
		return 5, "Presentation resources have a localized consumer-facing exposure."
	default:
		return 8, "This resource type receives the neutral exposure weight."
	}
}

func level(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MODERATE"
	default:
		return "LOW"
	}
}

func confidenceLevel(confidence int) string {
	switch {
	case confidence >= 80:
		return "HIGH"
	case confidence >= 50:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
