package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerEvaluationObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerEvaluationMetadata = true
	object.ThanosRulerEvaluationInterval = parseKubernetesDurationSetting(yamlMappingValue(spec, "evaluationInterval"))
	object.ThanosRulerResendDelay = parseKubernetesDurationSetting(yamlMappingValue(spec, "resendDelay"))
	object.ThanosRulerRuleOutageTolerance = parseKubernetesDurationSetting(yamlMappingValue(spec, "ruleOutageTolerance"))
	object.ThanosRulerRuleQueryOffset = parseKubernetesDurationSetting(yamlMappingValue(spec, "ruleQueryOffset"))
	object.ThanosRulerRuleGracePeriod = parseKubernetesDurationSetting(yamlMappingValue(spec, "ruleGracePeriod"))
	for _, setting := range []kubernetesDurationSetting{object.ThanosRulerEvaluationInterval, object.ThanosRulerResendDelay, object.ThanosRulerRuleOutageTolerance, object.ThanosRulerRuleQueryOffset, object.ThanosRulerRuleGracePeriod} {
		if setting.Declared && !setting.Valid {
			object.ThanosRulerEvaluationInvalidSettingCount++
		}
	}

	concurrent := yamlMappingValue(spec, "ruleConcurrentEval")
	object.ThanosRulerRuleConcurrentEvalDeclared = yamlValueDeclared(concurrent)
	if object.ThanosRulerRuleConcurrentEvalDeclared && concurrent.Kind == yaml.ScalarNode {
		value, err := strconv.ParseInt(strings.TrimSpace(concurrent.Value), 10, 32)
		if err == nil && value > 0 {
			object.ThanosRulerRuleConcurrentEval = value
			object.ThanosRulerRuleConcurrentEvalValid = true
		}
	}
	if object.ThanosRulerRuleConcurrentEvalDeclared && !object.ThanosRulerRuleConcurrentEvalValid {
		object.ThanosRulerEvaluationInvalidSettingCount++
	}

	versionChecks := []struct {
		declared bool
		major    int
		minor    int
	}{
		{object.ThanosRulerRuleOutageTolerance.Declared, 0, 30},
		{object.ThanosRulerRuleGracePeriod.Declared, 0, 30},
		{object.ThanosRulerRuleConcurrentEvalDeclared, 0, 37},
		{object.ThanosRulerRuleQueryOffset.Declared, 0, 38},
	}
	for _, check := range versionChecks {
		if !check.declared {
			continue
		}
		supported, evaluable := kubernetesPrometheusVersionAtLeast(object.PrometheusVersion, check.major, check.minor)
		object.ThanosRulerEvaluationVersionEvaluable = object.ThanosRulerEvaluationVersionEvaluable || evaluable
		if evaluable && !supported {
			object.ThanosRulerEvaluationUnsupportedSettingCount++
		}
	}
	object.ThanosRulerRestorationTimingInconsistent = object.ThanosRulerRuleOutageTolerance.Valid && object.ThanosRulerRuleGracePeriod.Valid && object.ThanosRulerRuleGracePeriod.Seconds > object.ThanosRulerRuleOutageTolerance.Seconds
}

func populateKubernetesThanosRulerEvaluationMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_evaluation_metadata"] = strconv.FormatBool(object.ThanosRulerEvaluationMetadata)
	populateKubernetesThanosRulerDurationMetadata(resource, "evaluation_interval", object.ThanosRulerEvaluationInterval)
	populateKubernetesThanosRulerDurationMetadata(resource, "resend_delay", object.ThanosRulerResendDelay)
	populateKubernetesThanosRulerDurationMetadata(resource, "rule_outage_tolerance", object.ThanosRulerRuleOutageTolerance)
	populateKubernetesThanosRulerDurationMetadata(resource, "rule_query_offset", object.ThanosRulerRuleQueryOffset)
	populateKubernetesThanosRulerDurationMetadata(resource, "rule_grace_period", object.ThanosRulerRuleGracePeriod)
	resource.Metadata["thanos_ruler_rule_concurrent_eval_declared"] = strconv.FormatBool(object.ThanosRulerRuleConcurrentEvalDeclared)
	resource.Metadata["thanos_ruler_rule_concurrent_eval_valid"] = strconv.FormatBool(object.ThanosRulerRuleConcurrentEvalValid)
	resource.Metadata["thanos_ruler_rule_concurrent_eval"] = strconv.FormatInt(object.ThanosRulerRuleConcurrentEval, 10)
	resource.Metadata["thanos_ruler_evaluation_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerEvaluationInvalidSettingCount)
	resource.Metadata["thanos_ruler_evaluation_version_evaluable"] = strconv.FormatBool(object.ThanosRulerEvaluationVersionEvaluable)
	resource.Metadata["thanos_ruler_evaluation_unsupported_setting_count"] = strconv.Itoa(object.ThanosRulerEvaluationUnsupportedSettingCount)
	resource.Metadata["thanos_ruler_restoration_timing_inconsistent"] = strconv.FormatBool(object.ThanosRulerRestorationTimingInconsistent)
}

func populateKubernetesThanosRulerDurationMetadata(resource *model.Resource, name string, setting kubernetesDurationSetting) {
	prefix := "thanos_ruler_" + name
	resource.Metadata[prefix+"_declared"] = strconv.FormatBool(setting.Declared)
	resource.Metadata[prefix+"_valid"] = strconv.FormatBool(setting.Valid)
	resource.Metadata[prefix+"_seconds"] = strconv.FormatInt(setting.Seconds, 10)
}
