package connector

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerAlertmanagerDeliveryObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerAlertmanagerDeliveryMetadata = true
	urls := yamlMappingValue(spec, "alertmanagersUrl")
	object.ThanosRulerAlertmanagerURLDeclared = yamlValueDeclared(urls)
	if object.ThanosRulerAlertmanagerURLDeclared {
		if urls.Kind != yaml.SequenceNode {
			object.ThanosRulerAlertmanagerURLInvalidCount++
		} else {
			seen := map[string]bool{}
			for _, item := range urls.Content {
				if item.Kind != yaml.ScalarNode {
					object.ThanosRulerAlertmanagerURLInvalidCount++
					continue
				}
				value := strings.TrimSpace(item.Value)
				scheme, loopback, valid := safeThanosRulerAlertmanagerURLMetadata(value)
				if !valid {
					object.ThanosRulerAlertmanagerURLInvalidCount++
					continue
				}
				if seen[value] {
					object.ThanosRulerAlertmanagerURLDuplicateCount++
					continue
				}
				seen[value] = true
				object.ThanosRulerAlertmanagerURLCount++
				if scheme == "http" && !loopback {
					object.ThanosRulerPlaintextAlertmanagerURLCount++
				}
			}
		}
	}
	config := yamlMappingValue(spec, "alertmanagersConfig")
	object.ThanosRulerAlertmanagerConfigDeclared = yamlValueDeclared(config)
	if object.ThanosRulerAlertmanagerConfigDeclared {
		invalid := 0
		parseKubernetesSecretKeySelector(config, &invalid)
		object.ThanosRulerAlertmanagerConfigValid = invalid == 0
		supported, evaluable := kubernetesPrometheusVersionAtLeast(object.PrometheusVersion, 0, 10)
		object.ThanosRulerAlertmanagerConfigVersionEvaluable = evaluable
		object.ThanosRulerAlertmanagerConfigVersionUnsupported = evaluable && !supported
	}
	object.ThanosRulerAlertmanagerDeliveryConfigured = object.ThanosRulerAlertmanagerConfigValid || object.ThanosRulerAlertmanagerURLCount > 0
}

func safeThanosRulerAlertmanagerURLMetadata(value string) (scheme string, loopback, valid bool) {
	if value == "" {
		return "", false, false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return "", false, false
	}
	scheme = strings.ToLower(parsed.Scheme)
	if separator := strings.LastIndex(scheme, "+"); separator >= 0 {
		discovery := scheme[:separator]
		if discovery != "dns" && discovery != "dnssrv" {
			return "", false, false
		}
		scheme = scheme[separator+1:]
	}
	if scheme != "http" && scheme != "https" {
		return "", false, false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if address := net.ParseIP(host); address != nil {
		loopback = address.IsLoopback()
	} else {
		loopback = host == "localhost" || strings.HasSuffix(host, ".localhost")
	}
	return scheme, loopback, true
}

func populateKubernetesThanosRulerAlertmanagerDeliveryMetadata(resource *model.Resource, object kubernetesObject) {
	metadata := resource.Metadata
	metadata["thanos_ruler_alertmanager_delivery_metadata"] = strconv.FormatBool(object.ThanosRulerAlertmanagerDeliveryMetadata)
	metadata["thanos_ruler_alertmanager_url_declared"] = strconv.FormatBool(object.ThanosRulerAlertmanagerURLDeclared)
	metadata["thanos_ruler_alertmanager_url_count"] = strconv.Itoa(object.ThanosRulerAlertmanagerURLCount)
	metadata["thanos_ruler_alertmanager_url_invalid_count"] = strconv.Itoa(object.ThanosRulerAlertmanagerURLInvalidCount)
	metadata["thanos_ruler_alertmanager_url_duplicate_count"] = strconv.Itoa(object.ThanosRulerAlertmanagerURLDuplicateCount)
	metadata["thanos_ruler_plaintext_alertmanager_url_count"] = strconv.Itoa(object.ThanosRulerPlaintextAlertmanagerURLCount)
	metadata["thanos_ruler_alertmanager_config_declared"] = strconv.FormatBool(object.ThanosRulerAlertmanagerConfigDeclared)
	metadata["thanos_ruler_alertmanager_config_valid"] = strconv.FormatBool(object.ThanosRulerAlertmanagerConfigValid)
	metadata["thanos_ruler_alertmanager_delivery_configured"] = strconv.FormatBool(object.ThanosRulerAlertmanagerDeliveryConfigured)
	metadata["thanos_ruler_alertmanager_config_version_evaluable"] = strconv.FormatBool(object.ThanosRulerAlertmanagerConfigVersionEvaluable)
	metadata["thanos_ruler_alertmanager_config_version_unsupported"] = strconv.FormatBool(object.ThanosRulerAlertmanagerConfigVersionUnsupported)
	metadata["thanos_ruler_selected_alert_rule_count"] = "0"
}
