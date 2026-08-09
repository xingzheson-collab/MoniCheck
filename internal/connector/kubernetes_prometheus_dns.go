package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesPrometheusDNSObject(object *kubernetesObject, spec *yaml.Node) {
	hostNetwork, declared, valid := parseKubernetesBooleanSetting(yamlMappingValue(spec, "hostNetwork"))
	object.PrometheusHostNetworkDeclared = declared
	object.PrometheusHostNetworkValid = valid
	object.PrometheusHostNetworkEnabled = valid && hostNetwork
	summary := parseKubernetesDNSSettings(spec, object.PrometheusHostNetworkEnabled)
	if declared && !valid {
		summary.InvalidCount++
	}
	object.PrometheusDNSMetadata = true
	object.PrometheusDNSPolicyDeclared = summary.DNSPolicyDeclared
	object.PrometheusDNSPolicyValid = summary.DNSPolicyValid
	object.PrometheusDNSPolicy = summary.DNSPolicy
	object.PrometheusDNSConfigDeclared = summary.DNSConfigDeclared
	object.PrometheusDNSConfigObjectValid = summary.DNSConfigObjectValid
	object.PrometheusDNSNameserverCount = summary.DNSNameserverCount
	object.PrometheusDNSInvalidSettingCount = summary.InvalidCount
	object.PrometheusServiceLinksDeclared = summary.ServiceLinksDeclared
	object.PrometheusServiceLinksValid = summary.ServiceLinksValid
	object.PrometheusServiceLinksEnabled = summary.ServiceLinksEnabled
}

func populateKubernetesPrometheusDNSMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["prometheus_dns_metadata"] = strconv.FormatBool(object.PrometheusDNSMetadata)
	resource.Metadata["prometheus_host_network_declared"] = strconv.FormatBool(object.PrometheusHostNetworkDeclared)
	resource.Metadata["prometheus_host_network_valid"] = strconv.FormatBool(object.PrometheusHostNetworkValid)
	resource.Metadata["prometheus_host_network_enabled"] = strconv.FormatBool(object.PrometheusHostNetworkEnabled)
	resource.Metadata["prometheus_dns_policy_declared"] = strconv.FormatBool(object.PrometheusDNSPolicyDeclared)
	resource.Metadata["prometheus_dns_policy_valid"] = strconv.FormatBool(object.PrometheusDNSPolicyValid)
	resource.Metadata["prometheus_dns_policy"] = object.PrometheusDNSPolicy
	resource.Metadata["prometheus_dns_config_declared"] = strconv.FormatBool(object.PrometheusDNSConfigDeclared)
	resource.Metadata["prometheus_dns_config_object_valid"] = strconv.FormatBool(object.PrometheusDNSConfigObjectValid)
	resource.Metadata["prometheus_dns_nameserver_count"] = strconv.Itoa(object.PrometheusDNSNameserverCount)
	resource.Metadata["prometheus_dns_invalid_setting_count"] = strconv.Itoa(object.PrometheusDNSInvalidSettingCount)
	resource.Metadata["prometheus_service_links_declared"] = strconv.FormatBool(object.PrometheusServiceLinksDeclared)
	resource.Metadata["prometheus_service_links_valid"] = strconv.FormatBool(object.PrometheusServiceLinksValid)
	resource.Metadata["prometheus_service_links_enabled"] = strconv.FormatBool(object.PrometheusServiceLinksEnabled)
}
