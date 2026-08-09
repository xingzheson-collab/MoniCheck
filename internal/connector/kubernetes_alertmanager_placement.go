package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesAlertmanagerPlacementObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPlacement(spec)
	object.AlertmanagerPlacementMetadata = true
	object.AlertmanagerNodeSelectorDeclared = summary.NodeSelectorDeclared
	object.AlertmanagerNodeSelectorValid = summary.NodeSelectorValid
	object.AlertmanagerNodeSelectorCount = summary.NodeSelectorCount
	object.AlertmanagerSchedulerNameDeclared = summary.SchedulerNameDeclared
	object.AlertmanagerSchedulerNameValid = summary.SchedulerNameValid
	object.AlertmanagerCustomScheduler = summary.CustomScheduler
	object.AlertmanagerPriorityClassNameDeclared = summary.PriorityClassNameDeclared
	object.AlertmanagerPriorityClassNameValid = summary.PriorityClassNameValid
	object.AlertmanagerTolerationsDeclared = summary.TolerationsDeclared
	object.AlertmanagerTolerationCount = summary.TolerationCount
	object.AlertmanagerTolerationInvalidSettingCount = summary.TolerationInvalidSettingCount
	object.AlertmanagerBroadTolerationCount = summary.BroadTolerationCount
	object.AlertmanagerIndefiniteNoExecuteTolerationCount = summary.IndefiniteNoExecuteTolerationCount
}

func populateKubernetesAlertmanagerPlacementMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_placement_metadata"] = strconv.FormatBool(object.AlertmanagerPlacementMetadata)
	resource.Metadata["alertmanager_node_selector_declared"] = strconv.FormatBool(object.AlertmanagerNodeSelectorDeclared)
	resource.Metadata["alertmanager_node_selector_valid"] = strconv.FormatBool(object.AlertmanagerNodeSelectorValid)
	resource.Metadata["alertmanager_node_selector_count"] = strconv.Itoa(object.AlertmanagerNodeSelectorCount)
	resource.Metadata["alertmanager_scheduler_name_declared"] = strconv.FormatBool(object.AlertmanagerSchedulerNameDeclared)
	resource.Metadata["alertmanager_scheduler_name_valid"] = strconv.FormatBool(object.AlertmanagerSchedulerNameValid)
	resource.Metadata["alertmanager_custom_scheduler"] = strconv.FormatBool(object.AlertmanagerCustomScheduler)
	resource.Metadata["alertmanager_priority_class_name_declared"] = strconv.FormatBool(object.AlertmanagerPriorityClassNameDeclared)
	resource.Metadata["alertmanager_priority_class_name_valid"] = strconv.FormatBool(object.AlertmanagerPriorityClassNameValid)
	resource.Metadata["alertmanager_tolerations_declared"] = strconv.FormatBool(object.AlertmanagerTolerationsDeclared)
	resource.Metadata["alertmanager_toleration_count"] = strconv.Itoa(object.AlertmanagerTolerationCount)
	resource.Metadata["alertmanager_toleration_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerTolerationInvalidSettingCount)
	resource.Metadata["alertmanager_broad_toleration_count"] = strconv.Itoa(object.AlertmanagerBroadTolerationCount)
	resource.Metadata["alertmanager_indefinite_no_execute_toleration_count"] = strconv.Itoa(object.AlertmanagerIndefiniteNoExecuteTolerationCount)
}
