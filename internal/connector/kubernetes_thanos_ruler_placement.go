package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesThanosRulerPlacementObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPlacement(spec)
	object.ThanosRulerPlacementMetadata = true
	object.ThanosRulerNodeSelectorDeclared = summary.NodeSelectorDeclared
	object.ThanosRulerNodeSelectorValid = summary.NodeSelectorValid
	object.ThanosRulerNodeSelectorCount = summary.NodeSelectorCount
	object.ThanosRulerSchedulerNameDeclared = summary.SchedulerNameDeclared
	object.ThanosRulerSchedulerNameValid = summary.SchedulerNameValid
	object.ThanosRulerCustomScheduler = summary.CustomScheduler
	object.ThanosRulerPriorityClassNameDeclared = summary.PriorityClassNameDeclared
	object.ThanosRulerPriorityClassNameValid = summary.PriorityClassNameValid
	object.ThanosRulerTolerationsDeclared = summary.TolerationsDeclared
	object.ThanosRulerTolerationCount = summary.TolerationCount
	object.ThanosRulerTolerationInvalidSettingCount = summary.TolerationInvalidSettingCount
	object.ThanosRulerBroadTolerationCount = summary.BroadTolerationCount
	object.ThanosRulerIndefiniteNoExecuteTolerationCount = summary.IndefiniteNoExecuteTolerationCount
}

func populateKubernetesThanosRulerPlacementMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_placement_metadata"] = strconv.FormatBool(object.ThanosRulerPlacementMetadata)
	resource.Metadata["thanos_ruler_node_selector_declared"] = strconv.FormatBool(object.ThanosRulerNodeSelectorDeclared)
	resource.Metadata["thanos_ruler_node_selector_valid"] = strconv.FormatBool(object.ThanosRulerNodeSelectorValid)
	resource.Metadata["thanos_ruler_node_selector_count"] = strconv.Itoa(object.ThanosRulerNodeSelectorCount)
	resource.Metadata["thanos_ruler_scheduler_name_declared"] = strconv.FormatBool(object.ThanosRulerSchedulerNameDeclared)
	resource.Metadata["thanos_ruler_scheduler_name_valid"] = strconv.FormatBool(object.ThanosRulerSchedulerNameValid)
	resource.Metadata["thanos_ruler_custom_scheduler"] = strconv.FormatBool(object.ThanosRulerCustomScheduler)
	resource.Metadata["thanos_ruler_priority_class_name_declared"] = strconv.FormatBool(object.ThanosRulerPriorityClassNameDeclared)
	resource.Metadata["thanos_ruler_priority_class_name_valid"] = strconv.FormatBool(object.ThanosRulerPriorityClassNameValid)
	resource.Metadata["thanos_ruler_tolerations_declared"] = strconv.FormatBool(object.ThanosRulerTolerationsDeclared)
	resource.Metadata["thanos_ruler_toleration_count"] = strconv.Itoa(object.ThanosRulerTolerationCount)
	resource.Metadata["thanos_ruler_toleration_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerTolerationInvalidSettingCount)
	resource.Metadata["thanos_ruler_broad_toleration_count"] = strconv.Itoa(object.ThanosRulerBroadTolerationCount)
	resource.Metadata["thanos_ruler_indefinite_no_execute_toleration_count"] = strconv.Itoa(object.ThanosRulerIndefiniteNoExecuteTolerationCount)
}
