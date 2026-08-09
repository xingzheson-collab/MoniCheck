package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerStatefulSetObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesStatefulSetStrategy(spec)
	object.ThanosRulerStatefulSetMetadata = true
	object.ThanosRulerPodManagementPolicyDeclared = summary.PodManagementDeclared
	object.ThanosRulerPodManagementPolicyValid = summary.PodManagementValid
	object.ThanosRulerPodManagementPolicy = summary.PodManagementPolicy
	object.ThanosRulerUpdateStrategyDeclared = summary.UpdateDeclared
	object.ThanosRulerUpdateStrategyObjectValid = summary.UpdateObjectValid
	object.ThanosRulerUpdateStrategyTypeValid = summary.UpdateTypeValid
	object.ThanosRulerUpdateStrategyType = summary.UpdateType
	object.ThanosRulerRollingUpdateDeclared = summary.RollingDeclared
	object.ThanosRulerRollingUpdateValid = summary.RollingValid
	object.ThanosRulerMaxUnavailableDeclared = summary.MaxUnavailableDeclared
	object.ThanosRulerMaxUnavailableValid = summary.MaxUnavailableValid
	object.ThanosRulerMaxUnavailable = summary.MaxUnavailableValue
	object.ThanosRulerMaxUnavailablePercent = summary.MaxUnavailablePercent
	object.ThanosRulerUpdateStrategyInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesThanosRulerStatefulSetMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_statefulset_metadata"] = strconv.FormatBool(object.ThanosRulerStatefulSetMetadata)
	resource.Metadata["thanos_ruler_pod_management_policy_declared"] = strconv.FormatBool(object.ThanosRulerPodManagementPolicyDeclared)
	resource.Metadata["thanos_ruler_pod_management_policy_valid"] = strconv.FormatBool(object.ThanosRulerPodManagementPolicyValid)
	resource.Metadata["thanos_ruler_pod_management_policy"] = object.ThanosRulerPodManagementPolicy
	resource.Metadata["thanos_ruler_update_strategy_declared"] = strconv.FormatBool(object.ThanosRulerUpdateStrategyDeclared)
	resource.Metadata["thanos_ruler_update_strategy_object_valid"] = strconv.FormatBool(object.ThanosRulerUpdateStrategyObjectValid)
	resource.Metadata["thanos_ruler_update_strategy_type_valid"] = strconv.FormatBool(object.ThanosRulerUpdateStrategyTypeValid)
	resource.Metadata["thanos_ruler_update_strategy_type"] = object.ThanosRulerUpdateStrategyType
	resource.Metadata["thanos_ruler_rolling_update_declared"] = strconv.FormatBool(object.ThanosRulerRollingUpdateDeclared)
	resource.Metadata["thanos_ruler_rolling_update_valid"] = strconv.FormatBool(object.ThanosRulerRollingUpdateValid)
	resource.Metadata["thanos_ruler_max_unavailable_declared"] = strconv.FormatBool(object.ThanosRulerMaxUnavailableDeclared)
	resource.Metadata["thanos_ruler_max_unavailable_valid"] = strconv.FormatBool(object.ThanosRulerMaxUnavailableValid)
	resource.Metadata["thanos_ruler_max_unavailable"] = strconv.FormatInt(object.ThanosRulerMaxUnavailable, 10)
	resource.Metadata["thanos_ruler_max_unavailable_percent"] = strconv.FormatBool(object.ThanosRulerMaxUnavailablePercent)
	resource.Metadata["thanos_ruler_effective_max_unavailable"] = strconv.FormatInt(kubernetesEffectiveMaxUnavailable(object.ThanosRulerMaxUnavailable, object.ThanosRulerMaxUnavailablePercent, object.PrometheusReplicas), 10)
	resource.Metadata["thanos_ruler_update_strategy_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerUpdateStrategyInvalidSettingCount)
}
