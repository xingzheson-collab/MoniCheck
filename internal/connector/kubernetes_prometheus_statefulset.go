package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusStatefulSetObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesStatefulSetStrategy(spec)
	object.PrometheusStatefulSetMetadata = true
	object.PrometheusStatefulSetApplicable = object.Kind != "PrometheusAgent" || object.PrometheusAgentMode != "daemonset"
	object.PrometheusPodManagementPolicyDeclared = summary.PodManagementDeclared
	object.PrometheusPodManagementPolicyValid = summary.PodManagementValid
	object.PrometheusPodManagementPolicy = summary.PodManagementPolicy
	object.PrometheusUpdateStrategyDeclared = summary.UpdateDeclared
	object.PrometheusUpdateStrategyObjectValid = summary.UpdateObjectValid
	object.PrometheusUpdateStrategyTypeValid = summary.UpdateTypeValid
	object.PrometheusUpdateStrategyType = summary.UpdateType
	object.PrometheusRollingUpdateDeclared = summary.RollingDeclared
	object.PrometheusRollingUpdateValid = summary.RollingValid
	object.PrometheusMaxUnavailableDeclared = summary.MaxUnavailableDeclared
	object.PrometheusMaxUnavailableValid = summary.MaxUnavailableValid
	object.PrometheusMaxUnavailable = summary.MaxUnavailableValue
	object.PrometheusMaxUnavailablePercent = summary.MaxUnavailablePercent
	object.PrometheusUpdateStrategyInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesPrometheusStatefulSetMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_statefulset_metadata"] = strconv.FormatBool(object.PrometheusStatefulSetMetadata)
	resource.Metadata["prometheus_statefulset_applicable"] = strconv.FormatBool(object.PrometheusStatefulSetApplicable)
	resource.Metadata["prometheus_pod_management_policy_declared"] = strconv.FormatBool(object.PrometheusPodManagementPolicyDeclared)
	resource.Metadata["prometheus_pod_management_policy_valid"] = strconv.FormatBool(object.PrometheusPodManagementPolicyValid)
	resource.Metadata["prometheus_pod_management_policy"] = object.PrometheusPodManagementPolicy
	resource.Metadata["prometheus_update_strategy_declared"] = strconv.FormatBool(object.PrometheusUpdateStrategyDeclared)
	resource.Metadata["prometheus_update_strategy_object_valid"] = strconv.FormatBool(object.PrometheusUpdateStrategyObjectValid)
	resource.Metadata["prometheus_update_strategy_type_valid"] = strconv.FormatBool(object.PrometheusUpdateStrategyTypeValid)
	resource.Metadata["prometheus_update_strategy_type"] = object.PrometheusUpdateStrategyType
	resource.Metadata["prometheus_rolling_update_declared"] = strconv.FormatBool(object.PrometheusRollingUpdateDeclared)
	resource.Metadata["prometheus_rolling_update_valid"] = strconv.FormatBool(object.PrometheusRollingUpdateValid)
	resource.Metadata["prometheus_max_unavailable_declared"] = strconv.FormatBool(object.PrometheusMaxUnavailableDeclared)
	resource.Metadata["prometheus_max_unavailable_valid"] = strconv.FormatBool(object.PrometheusMaxUnavailableValid)
	resource.Metadata["prometheus_max_unavailable"] = strconv.FormatInt(object.PrometheusMaxUnavailable, 10)
	resource.Metadata["prometheus_max_unavailable_percent"] = strconv.FormatBool(object.PrometheusMaxUnavailablePercent)
	resource.Metadata["prometheus_effective_max_unavailable"] = strconv.FormatInt(kubernetesEffectiveMaxUnavailable(object.PrometheusMaxUnavailable, object.PrometheusMaxUnavailablePercent, object.PrometheusReplicas), 10)
	resource.Metadata["prometheus_update_strategy_invalid_setting_count"] = strconv.Itoa(object.PrometheusUpdateStrategyInvalidSettingCount)
}
