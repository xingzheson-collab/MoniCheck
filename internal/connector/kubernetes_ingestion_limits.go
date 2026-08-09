package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func parseKubernetesIngestionLimits(spec *yaml.Node, enforced bool) kubernetesIngestionLimits {
	prefix := ""
	if enforced {
		prefix = "enforced"
	}
	field := func(name string) string {
		if prefix == "" {
			return name
		}
		return prefix + strings.ToUpper(name[:1]) + name[1:]
	}
	return kubernetesIngestionLimits{
		Sample:           parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("sampleLimit"))),
		Target:           parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("targetLimit"))),
		Label:            parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("labelLimit"))),
		LabelNameLength:  parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("labelNameLengthLimit"))),
		LabelValueLength: parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("labelValueLengthLimit"))),
		Body:             parseKubernetesByteSizeLimit(yamlMappingValue(spec, field("bodySizeLimit"))),
		KeepDropped:      parseKubernetesPositiveIntegerLimit(yamlMappingValue(spec, field("keepDroppedTargets"))),
	}
}

func parseKubernetesPositiveIntegerLimit(node *yaml.Node) kubernetesIngestionLimit {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return kubernetesIngestionLimit{}
	}
	value, err := strconv.ParseInt(strings.TrimSpace(node.Value), 10, 64)
	return kubernetesIngestionLimit{Declared: true, Valid: err == nil && value > 0, Value: value}
}

func parseKubernetesByteSizeLimit(node *yaml.Node) kubernetesIngestionLimit {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return kubernetesIngestionLimit{}
	}
	value, valid := parsePrometheusByteSize(strings.TrimSpace(node.Value))
	return kubernetesIngestionLimit{Declared: true, Valid: valid, Value: value}
}

func populateKubernetesPrometheusEnforcedLimitMetadata(resource *model.Resource, limits kubernetesIngestionLimits) {
	populateKubernetesIngestionLimitMetadata(resource, "prometheus_enforced", limits)
}

func populateKubernetesMonitorIngestionLimitMetadata(resource *model.Resource, limits kubernetesIngestionLimits) {
	populateKubernetesIngestionLimitMetadata(resource, "monitor", limits)
}

func populateKubernetesIngestionLimitMetadata(resource *model.Resource, prefix string, limits kubernetesIngestionLimits) {
	values := []struct {
		name  string
		limit kubernetesIngestionLimit
	}{
		{"sample_limit", limits.Sample},
		{"target_limit", limits.Target},
		{"label_limit", limits.Label},
		{"label_name_length_limit", limits.LabelNameLength},
		{"label_value_length_limit", limits.LabelValueLength},
		{"body_size_limit", limits.Body},
		{"keep_dropped_targets_limit", limits.KeepDropped},
	}
	invalidCount := 0
	for _, item := range values {
		base := prefix + "_" + item.name
		resource.Metadata[base+"_declared"] = strconv.FormatBool(item.limit.Declared)
		resource.Metadata[base+"_valid"] = strconv.FormatBool(item.limit.Valid)
		resource.Metadata[base+"_value"] = strconv.FormatInt(item.limit.Value, 10)
		if item.limit.Declared && !item.limit.Valid {
			invalidCount++
		}
	}
	resource.Metadata[prefix+"_ingestion_limit_invalid_setting_count"] = strconv.Itoa(invalidCount)
}

var kubernetesIngestionCoverageDimensions = []struct {
	name     string
	localKey string
	global   func(kubernetesIngestionLimits) kubernetesIngestionLimit
}{
	{"sample", "monitor_sample_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.Sample }},
	{"target", "monitor_target_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.Target }},
	{"label", "monitor_label_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.Label }},
	{"label_name_length", "monitor_label_name_length_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.LabelNameLength }},
	{"label_value_length", "monitor_label_value_length_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.LabelValueLength }},
	{"body", "monitor_body_size_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.Body }},
	{"keep_dropped_targets", "monitor_keep_dropped_targets_limit_valid", func(limits kubernetesIngestionLimits) kubernetesIngestionLimit { return limits.KeepDropped }},
}
