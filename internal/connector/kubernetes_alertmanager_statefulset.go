package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesAlertmanagerStatefulSetObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesStatefulSetStrategy(spec)
	object.AlertmanagerStatefulSetMetadata = true
	object.AlertmanagerPodManagementPolicyDeclared = summary.PodManagementDeclared
	object.AlertmanagerPodManagementPolicyValid = summary.PodManagementValid
	object.AlertmanagerPodManagementPolicy = summary.PodManagementPolicy
	object.AlertmanagerUpdateStrategyDeclared = summary.UpdateDeclared
	object.AlertmanagerUpdateStrategyObjectValid = summary.UpdateObjectValid
	object.AlertmanagerUpdateStrategyTypeValid = summary.UpdateTypeValid
	object.AlertmanagerUpdateStrategyType = summary.UpdateType
	object.AlertmanagerRollingUpdateDeclared = summary.RollingDeclared
	object.AlertmanagerRollingUpdateValid = summary.RollingValid
	object.AlertmanagerMaxUnavailableDeclared = summary.MaxUnavailableDeclared
	object.AlertmanagerMaxUnavailableValid = summary.MaxUnavailableValid
	object.AlertmanagerMaxUnavailable = summary.MaxUnavailableValue
	object.AlertmanagerMaxUnavailablePercent = summary.MaxUnavailablePercent
	object.AlertmanagerUpdateStrategyInvalidSettingCount = summary.InvalidCount
}

func populateKubernetesAlertmanagerStatefulSetMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_statefulset_metadata"] = strconv.FormatBool(object.AlertmanagerStatefulSetMetadata)
	resource.Metadata["alertmanager_pod_management_policy_declared"] = strconv.FormatBool(object.AlertmanagerPodManagementPolicyDeclared)
	resource.Metadata["alertmanager_pod_management_policy_valid"] = strconv.FormatBool(object.AlertmanagerPodManagementPolicyValid)
	resource.Metadata["alertmanager_pod_management_policy"] = object.AlertmanagerPodManagementPolicy
	resource.Metadata["alertmanager_update_strategy_declared"] = strconv.FormatBool(object.AlertmanagerUpdateStrategyDeclared)
	resource.Metadata["alertmanager_update_strategy_object_valid"] = strconv.FormatBool(object.AlertmanagerUpdateStrategyObjectValid)
	resource.Metadata["alertmanager_update_strategy_type_valid"] = strconv.FormatBool(object.AlertmanagerUpdateStrategyTypeValid)
	resource.Metadata["alertmanager_update_strategy_type"] = object.AlertmanagerUpdateStrategyType
	resource.Metadata["alertmanager_rolling_update_declared"] = strconv.FormatBool(object.AlertmanagerRollingUpdateDeclared)
	resource.Metadata["alertmanager_rolling_update_valid"] = strconv.FormatBool(object.AlertmanagerRollingUpdateValid)
	resource.Metadata["alertmanager_max_unavailable_declared"] = strconv.FormatBool(object.AlertmanagerMaxUnavailableDeclared)
	resource.Metadata["alertmanager_max_unavailable_valid"] = strconv.FormatBool(object.AlertmanagerMaxUnavailableValid)
	resource.Metadata["alertmanager_max_unavailable"] = strconv.FormatInt(object.AlertmanagerMaxUnavailable, 10)
	resource.Metadata["alertmanager_max_unavailable_percent"] = strconv.FormatBool(object.AlertmanagerMaxUnavailablePercent)
	resource.Metadata["alertmanager_effective_max_unavailable"] = strconv.FormatInt(kubernetesEffectiveMaxUnavailable(object.AlertmanagerMaxUnavailable, object.AlertmanagerMaxUnavailablePercent, object.AlertmanagerReplicas), 10)
	resource.Metadata["alertmanager_update_strategy_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerUpdateStrategyInvalidSettingCount)
}
