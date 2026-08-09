package connector

import (
	"strconv"

	"monicheck/internal/model"

	"gopkg.in/yaml.v3"
)

func populateKubernetesAlertmanagerDNSObject(object *kubernetesObject, spec *yaml.Node) {
	summary := parseKubernetesDNSSettings(spec, object.AlertmanagerHostNetworkEnabled)
	object.AlertmanagerDNSMetadata = true
	object.AlertmanagerDNSPolicyDeclared = summary.DNSPolicyDeclared
	object.AlertmanagerDNSPolicyValid = summary.DNSPolicyValid
	object.AlertmanagerDNSPolicy = summary.DNSPolicy
	object.AlertmanagerDNSConfigDeclared = summary.DNSConfigDeclared
	object.AlertmanagerDNSConfigObjectValid = summary.DNSConfigObjectValid
	object.AlertmanagerDNSNameserverCount = summary.DNSNameserverCount
	object.AlertmanagerDNSInvalidSettingCount = summary.InvalidCount
	object.AlertmanagerServiceLinksDeclared = summary.ServiceLinksDeclared
	object.AlertmanagerServiceLinksValid = summary.ServiceLinksValid
	object.AlertmanagerServiceLinksEnabled = summary.ServiceLinksEnabled
}

func populateKubernetesAlertmanagerDNSMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["alertmanager_dns_metadata"] = strconv.FormatBool(object.AlertmanagerDNSMetadata)
	resource.Metadata["alertmanager_dns_policy_declared"] = strconv.FormatBool(object.AlertmanagerDNSPolicyDeclared)
	resource.Metadata["alertmanager_dns_policy_valid"] = strconv.FormatBool(object.AlertmanagerDNSPolicyValid)
	resource.Metadata["alertmanager_dns_policy"] = object.AlertmanagerDNSPolicy
	resource.Metadata["alertmanager_dns_config_declared"] = strconv.FormatBool(object.AlertmanagerDNSConfigDeclared)
	resource.Metadata["alertmanager_dns_config_object_valid"] = strconv.FormatBool(object.AlertmanagerDNSConfigObjectValid)
	resource.Metadata["alertmanager_dns_nameserver_count"] = strconv.Itoa(object.AlertmanagerDNSNameserverCount)
	resource.Metadata["alertmanager_dns_invalid_setting_count"] = strconv.Itoa(object.AlertmanagerDNSInvalidSettingCount)
	resource.Metadata["alertmanager_service_links_declared"] = strconv.FormatBool(object.AlertmanagerServiceLinksDeclared)
	resource.Metadata["alertmanager_service_links_valid"] = strconv.FormatBool(object.AlertmanagerServiceLinksValid)
	resource.Metadata["alertmanager_service_links_enabled"] = strconv.FormatBool(object.AlertmanagerServiceLinksEnabled)
}
