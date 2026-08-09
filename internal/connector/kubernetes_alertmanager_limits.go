package connector

import (
	"math"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesAlertmanagerLimitsObject(object *kubernetesObject, spec *yaml.Node) {
	limits := yamlMappingValue(spec, "limits")
	object.AlertmanagerLimitsDeclared = yamlValueDeclared(limits)
	if !object.AlertmanagerLimitsDeclared {
		return
	}
	object.AlertmanagerLimitsObjectValid = limits.Kind == yaml.MappingNode
	if !object.AlertmanagerLimitsObjectValid {
		object.AlertmanagerLimitsInvalidSettingCount = 1
		return
	}

	maxSilences := yamlMappingValue(limits, "maxSilences")
	object.AlertmanagerMaxSilencesDeclared = yamlValueDeclared(maxSilences)
	if object.AlertmanagerMaxSilencesDeclared && maxSilences.Kind == yaml.ScalarNode {
		value, err := strconv.ParseInt(strings.TrimSpace(maxSilences.Value), 10, 64)
		if err == nil && value >= 0 && value <= math.MaxInt32 {
			object.AlertmanagerMaxSilencesValid = true
			object.AlertmanagerMaxSilences = value
		}
	}
	if object.AlertmanagerMaxSilencesDeclared && !object.AlertmanagerMaxSilencesValid {
		object.AlertmanagerLimitsInvalidSettingCount++
	}

	maxBytes := yamlMappingValue(limits, "maxPerSilenceBytes")
	object.AlertmanagerMaxPerSilenceBytesDeclared = yamlValueDeclared(maxBytes)
	if object.AlertmanagerMaxPerSilenceBytesDeclared && maxBytes.Kind == yaml.ScalarNode {
		object.AlertmanagerMaxPerSilenceBytes, object.AlertmanagerMaxPerSilenceBytesValid = parseAlertmanagerLimitByteSize(maxBytes.Value)
	}
	if object.AlertmanagerMaxPerSilenceBytesDeclared && !object.AlertmanagerMaxPerSilenceBytesValid {
		object.AlertmanagerLimitsInvalidSettingCount++
	}

	supported, evaluable := kubernetesPrometheusVersionAtLeast(object.AlertmanagerVersion, 0, 28)
	object.AlertmanagerLimitsVersionEvaluable = evaluable
	usesLimits := (object.AlertmanagerMaxSilencesDeclared && object.AlertmanagerMaxSilencesValid) || (object.AlertmanagerMaxPerSilenceBytesDeclared && object.AlertmanagerMaxPerSilenceBytesValid)
	object.AlertmanagerLimitsVersionUnsupported = usesLimits && evaluable && !supported
}

func populateKubernetesAlertmanagerLimitsMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_limits_declared"] = strconv.FormatBool(object.AlertmanagerLimitsDeclared)
	resource.Metadata["alertmanager_limits_object_valid"] = strconv.FormatBool(object.AlertmanagerLimitsObjectValid)
	resource.Metadata["alertmanager_limits_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerLimitsInvalidSettingCount)
	resource.Metadata["alertmanager_max_silences_declared"] = strconv.FormatBool(object.AlertmanagerMaxSilencesDeclared)
	resource.Metadata["alertmanager_max_silences_valid"] = strconv.FormatBool(object.AlertmanagerMaxSilencesValid)
	resource.Metadata["alertmanager_max_silences"] = strconv.FormatInt(object.AlertmanagerMaxSilences, 10)
	resource.Metadata["alertmanager_max_silences_enabled"] = strconv.FormatBool(object.AlertmanagerMaxSilencesValid && object.AlertmanagerMaxSilences > 0)
	resource.Metadata["alertmanager_max_per_silence_bytes_declared"] = strconv.FormatBool(object.AlertmanagerMaxPerSilenceBytesDeclared)
	resource.Metadata["alertmanager_max_per_silence_bytes_valid"] = strconv.FormatBool(object.AlertmanagerMaxPerSilenceBytesValid)
	resource.Metadata["alertmanager_max_per_silence_bytes"] = strconv.FormatInt(object.AlertmanagerMaxPerSilenceBytes, 10)
	resource.Metadata["alertmanager_max_per_silence_bytes_enabled"] = strconv.FormatBool(object.AlertmanagerMaxPerSilenceBytesValid && object.AlertmanagerMaxPerSilenceBytes > 0)
	resource.Metadata["alertmanager_limits_version_evaluable"] = strconv.FormatBool(object.AlertmanagerLimitsVersionEvaluable)
	resource.Metadata["alertmanager_limits_version_unsupported"] = strconv.FormatBool(object.AlertmanagerLimitsVersionUnsupported)
}

func parseAlertmanagerLimitByteSize(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	matches := storageQuantityPattern.FindStringSubmatch(value)
	if len(matches) == 3 {
		number, err := strconv.ParseFloat(matches[1], 64)
		if err == nil && number == 0 {
			return 0, true
		}
	}
	return parsePrometheusByteSize(value)
}
