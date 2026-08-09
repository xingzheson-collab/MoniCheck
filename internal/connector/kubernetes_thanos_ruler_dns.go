package connector

import (
	"strconv"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerDNSObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesDNSSettings(spec, false)
	object.ThanosRulerHostNetworkUnsupported = yamlValueDeclared(yamlMappingValue(spec, "hostNetwork"))
	if object.ThanosRulerHostNetworkUnsupported {
		summary.InvalidCount++
	}
	object.ThanosRulerDNSMetadata = true
	object.ThanosRulerDNSPolicyDeclared = summary.DNSPolicyDeclared
	object.ThanosRulerDNSPolicyValid = summary.DNSPolicyValid
	object.ThanosRulerDNSPolicy = summary.DNSPolicy
	object.ThanosRulerDNSConfigDeclared = summary.DNSConfigDeclared
	object.ThanosRulerDNSConfigObjectValid = summary.DNSConfigObjectValid
	object.ThanosRulerDNSNameserverCount = summary.DNSNameserverCount
	object.ThanosRulerDNSInvalidSettingCount = summary.InvalidCount
	object.ThanosRulerServiceLinksDeclared = summary.ServiceLinksDeclared
	object.ThanosRulerServiceLinksValid = summary.ServiceLinksValid
	object.ThanosRulerServiceLinksEnabled = summary.ServiceLinksEnabled
}

func populateKubernetesThanosRulerDNSMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_dns_metadata"] = strconv.FormatBool(object.ThanosRulerDNSMetadata)
	resource.Metadata["thanos_ruler_dns_policy_declared"] = strconv.FormatBool(object.ThanosRulerDNSPolicyDeclared)
	resource.Metadata["thanos_ruler_dns_policy_valid"] = strconv.FormatBool(object.ThanosRulerDNSPolicyValid)
	resource.Metadata["thanos_ruler_dns_policy"] = object.ThanosRulerDNSPolicy
	resource.Metadata["thanos_ruler_dns_config_declared"] = strconv.FormatBool(object.ThanosRulerDNSConfigDeclared)
	resource.Metadata["thanos_ruler_dns_config_object_valid"] = strconv.FormatBool(object.ThanosRulerDNSConfigObjectValid)
	resource.Metadata["thanos_ruler_dns_nameserver_count"] = strconv.Itoa(object.ThanosRulerDNSNameserverCount)
	resource.Metadata["thanos_ruler_dns_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerDNSInvalidSettingCount)
	resource.Metadata["thanos_ruler_service_links_declared"] = strconv.FormatBool(object.ThanosRulerServiceLinksDeclared)
	resource.Metadata["thanos_ruler_service_links_valid"] = strconv.FormatBool(object.ThanosRulerServiceLinksValid)
	resource.Metadata["thanos_ruler_service_links_enabled"] = strconv.FormatBool(object.ThanosRulerServiceLinksEnabled)
	resource.Metadata["thanos_ruler_host_network_unsupported"] = strconv.FormatBool(object.ThanosRulerHostNetworkUnsupported)
}
