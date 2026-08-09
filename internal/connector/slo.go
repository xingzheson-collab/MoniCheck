package connector

import (
	"strings"

	"monicheck/internal/model"
)

var sloNameKeys = []string{
	"slo",
	"slo_name",
	"sloth_slo",
	"pyrra_slo",
	"service_level_objective",
}

var sloObjectiveKeys = []string{
	"objective",
	"slo_objective",
	"sloth_objective",
	"target_objective",
}

var sloWindowKeys = []string{
	"window",
	"slo_window",
	"sloth_window",
	"pyrra_window",
	"lookback",
}

func annotateSLORuleMetadata(resource *model.Resource) {
	if resource == nil || (resource.Type != model.ResourceTypeAlertRule && resource.Type != model.ResourceTypeRecordingRule) {
		return
	}
	if resource.Metadata == nil {
		resource.Metadata = map[string]string{}
	}

	sloName := firstResourceValue(*resource, sloNameKeys)
	objective := firstResourceValue(*resource, sloObjectiveKeys)
	window := firstResourceValue(*resource, sloWindowKeys)
	if sloName != "" {
		resource.Metadata[model.MetadataSLOName] = sloName
	}
	if objective != "" {
		resource.Metadata[model.MetadataSLOObjective] = objective
	}
	if window != "" {
		resource.Metadata[model.MetadataSLOWindow] = window
	}
	if sloName != "" || objective != "" || hasSLOIdentity(*resource) {
		resource.Metadata[model.MetadataSLORule] = "true"
	}
}

func firstResourceValue(resource model.Resource, keys []string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(resource.Labels[key]); value != "" {
			return value
		}
		if value := strings.TrimSpace(resource.Metadata[key]); value != "" {
			return value
		}
	}
	return ""
}

func hasSLOIdentity(resource model.Resource) bool {
	for _, value := range []string{
		resource.Name,
		resource.Metadata[model.MetadataRecordingRuleOutput],
		resource.Metadata[model.MetadataRuleGroup],
	} {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if strings.HasPrefix(normalized, "slo:") || strings.HasPrefix(normalized, "sli:") ||
			strings.Contains(normalized, "error_budget") || strings.Contains(normalized, "errorbudget") ||
			strings.Contains(normalized, "burn_rate") || strings.Contains(normalized, "burnrate") {
			return true
		}
		for _, token := range strings.FieldsFunc(normalized, func(r rune) bool {
			return r == ':' || r == '/' || r == '_' || r == '-' || r == '.' || r == ' '
		}) {
			if token == "slo" || token == "sli" || token == "sloth" || token == "pyrra" {
				return true
			}
		}
	}
	return false
}
