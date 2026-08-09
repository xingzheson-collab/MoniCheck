package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusPlacementObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesPlacement(spec)
	object.PrometheusPlacementMetadata = true
	object.PrometheusNodeSelectorDeclared = summary.NodeSelectorDeclared
	object.PrometheusNodeSelectorValid = summary.NodeSelectorValid
	object.PrometheusNodeSelectorCount = summary.NodeSelectorCount
	object.PrometheusSchedulerNameDeclared = summary.SchedulerNameDeclared
	object.PrometheusSchedulerNameValid = summary.SchedulerNameValid
	object.PrometheusCustomScheduler = summary.CustomScheduler
	object.PrometheusPriorityClassNameDeclared = summary.PriorityClassNameDeclared
	object.PrometheusPriorityClassNameValid = summary.PriorityClassNameValid
	object.PrometheusTolerationsDeclared = summary.TolerationsDeclared
	object.PrometheusTolerationCount = summary.TolerationCount
	object.PrometheusTolerationInvalidSettingCount = summary.TolerationInvalidSettingCount
	object.PrometheusBroadTolerationCount = summary.BroadTolerationCount
	object.PrometheusIndefiniteNoExecuteTolerationCount = summary.IndefiniteNoExecuteTolerationCount
}

func populateKubernetesPrometheusPlacementMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_placement_metadata"] = strconv.FormatBool(object.PrometheusPlacementMetadata)
	resource.Metadata["prometheus_node_selector_declared"] = strconv.FormatBool(object.PrometheusNodeSelectorDeclared)
	resource.Metadata["prometheus_node_selector_valid"] = strconv.FormatBool(object.PrometheusNodeSelectorValid)
	resource.Metadata["prometheus_node_selector_count"] = strconv.Itoa(object.PrometheusNodeSelectorCount)
	resource.Metadata["prometheus_scheduler_name_declared"] = strconv.FormatBool(object.PrometheusSchedulerNameDeclared)
	resource.Metadata["prometheus_scheduler_name_valid"] = strconv.FormatBool(object.PrometheusSchedulerNameValid)
	resource.Metadata["prometheus_custom_scheduler"] = strconv.FormatBool(object.PrometheusCustomScheduler)
	resource.Metadata["prometheus_priority_class_name_declared"] = strconv.FormatBool(object.PrometheusPriorityClassNameDeclared)
	resource.Metadata["prometheus_priority_class_name_valid"] = strconv.FormatBool(object.PrometheusPriorityClassNameValid)
	resource.Metadata["prometheus_tolerations_declared"] = strconv.FormatBool(object.PrometheusTolerationsDeclared)
	resource.Metadata["prometheus_toleration_count"] = strconv.Itoa(object.PrometheusTolerationCount)
	resource.Metadata["prometheus_toleration_invalid_setting_count"] = strconv.Itoa(object.PrometheusTolerationInvalidSettingCount)
	resource.Metadata["prometheus_broad_toleration_count"] = strconv.Itoa(object.PrometheusBroadTolerationCount)
	resource.Metadata["prometheus_indefinite_no_execute_toleration_count"] = strconv.Itoa(object.PrometheusIndefiniteNoExecuteTolerationCount)
}
