package connector

import (
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func populateKubernetesThanosRulerWebObject(object *kubernetesObject, spec *yaml.Node) {
	object.ThanosRulerWebMetadata = true
	web := yamlMappingValue(spec, "web")
	object.ThanosRulerWebDeclared = yamlValueDeclared(web)
	if !object.ThanosRulerWebDeclared {
		return
	}
	object.ThanosRulerWebObjectValid = web.Kind == yaml.MappingNode
	if !object.ThanosRulerWebObjectValid {
		object.ThanosRulerWebInvalidSettingCount = 1
		return
	}

	tlsConfig := yamlMappingValue(web, "tlsConfig")
	object.ThanosRulerWebTLSDeclared = yamlValueDeclared(tlsConfig)
	if object.ThanosRulerWebTLSDeclared {
		parseKubernetesThanosRulerWebTLS(object, tlsConfig)
	}

	httpConfig := yamlMappingValue(web, "httpConfig")
	object.ThanosRulerWebHTTPConfigDeclared = yamlValueDeclared(httpConfig)
	if object.ThanosRulerWebHTTPConfigDeclared {
		parseKubernetesThanosRulerWebHTTP(object, httpConfig)
	}
}

func parseKubernetesThanosRulerWebTLS(object *kubernetesObject, tlsConfig *yaml.Node) {
	if tlsConfig.Kind != yaml.MappingNode {
		object.ThanosRulerWebInvalidSettingCount++
		return
	}
	certSources := 0
	keySources := 0
	for _, field := range []struct {
		name    string
		mapping bool
		count   *int
	}{
		{name: "cert", mapping: true, count: &certSources},
		{name: "certFile", count: &certSources},
		{name: "keySecret", mapping: true, count: &keySources},
		{name: "keyFile", count: &keySources},
	} {
		node := yamlMappingValue(tlsConfig, field.name)
		if !yamlValueDeclared(node) {
			continue
		}
		valid := node.Kind == yaml.ScalarNode && strings.TrimSpace(node.Value) != ""
		if field.mapping {
			valid = node.Kind == yaml.MappingNode
		}
		if !valid {
			object.ThanosRulerWebInvalidSettingCount++
			continue
		}
		*field.count++
	}
	if certSources != 1 {
		object.ThanosRulerWebInvalidSettingCount++
	}
	if keySources != 1 {
		object.ThanosRulerWebInvalidSettingCount++
	}
	object.ThanosRulerWebTLSComplete = certSources == 1 && keySources == 1 && object.ThanosRulerWebInvalidSettingCount == 0
}

func parseKubernetesThanosRulerWebHTTP(object *kubernetesObject, httpConfig *yaml.Node) {
	if httpConfig.Kind != yaml.MappingNode {
		object.ThanosRulerWebInvalidSettingCount++
		return
	}
	object.ThanosRulerWebHTTP2Enabled, object.ThanosRulerWebHTTP2Declared, object.ThanosRulerWebHTTP2Valid = parseKubernetesBooleanSetting(yamlMappingValue(httpConfig, "http2"))
	if object.ThanosRulerWebHTTP2Declared && !object.ThanosRulerWebHTTP2Valid {
		object.ThanosRulerWebInvalidSettingCount++
	}
	headers := yamlMappingValue(httpConfig, "headers")
	if yamlValueDeclared(headers) {
		if headers.Kind != yaml.MappingNode {
			object.ThanosRulerWebInvalidSettingCount++
		} else if contentSecurityPolicy := yamlMappingValue(headers, "contentSecurityPolicy"); yamlValueDeclared(contentSecurityPolicy) && contentSecurityPolicy.Kind != yaml.ScalarNode {
			object.ThanosRulerWebInvalidSettingCount++
		}
	}
}

func populateKubernetesThanosRulerWebMetadata(resource *model.Resource, object kubernetesObject) {
	resource.Metadata["thanos_ruler_web_metadata"] = strconv.FormatBool(object.ThanosRulerWebMetadata)
	resource.Metadata["thanos_ruler_web_declared"] = strconv.FormatBool(object.ThanosRulerWebDeclared)
	resource.Metadata["thanos_ruler_web_object_valid"] = strconv.FormatBool(object.ThanosRulerWebObjectValid)
	resource.Metadata["thanos_ruler_web_invalid_setting_count"] = strconv.Itoa(object.ThanosRulerWebInvalidSettingCount)
	resource.Metadata["thanos_ruler_web_tls_declared"] = strconv.FormatBool(object.ThanosRulerWebTLSDeclared)
	resource.Metadata["thanos_ruler_web_tls_complete"] = strconv.FormatBool(object.ThanosRulerWebTLSComplete)
	resource.Metadata["thanos_ruler_web_http_config_declared"] = strconv.FormatBool(object.ThanosRulerWebHTTPConfigDeclared)
	resource.Metadata["thanos_ruler_web_http2_declared"] = strconv.FormatBool(object.ThanosRulerWebHTTP2Declared)
	resource.Metadata["thanos_ruler_web_http2_valid"] = strconv.FormatBool(object.ThanosRulerWebHTTP2Valid)
	resource.Metadata["thanos_ruler_web_http2_enabled"] = strconv.FormatBool(object.ThanosRulerWebHTTP2Enabled)
}
