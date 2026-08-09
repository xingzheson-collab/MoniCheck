package analyzer

import (
	"net/netip"
	"net/url"
	"strings"

	"monicheck/internal/model"
)

type datasourceEndpointInfo struct {
	Configured      bool
	Valid           bool
	Scheme          string
	Host            string
	HostScope       string
	HostFingerprint string
}

func datasourceEndpoint(resource model.Resource) datasourceEndpointInfo {
	metadata := resource.Metadata
	if _, derived := metadata[model.MetadataDatasourceURLConfigured]; derived {
		return datasourceEndpointInfo{
			Configured:      isTruthy(metadata[model.MetadataDatasourceURLConfigured]),
			Valid:           isTruthy(metadata[model.MetadataDatasourceURLValid]),
			Scheme:          strings.ToLower(strings.TrimSpace(metadata[model.MetadataDatasourceURLScheme])),
			HostScope:       strings.ToLower(strings.TrimSpace(metadata[model.MetadataDatasourceURLHostScope])),
			HostFingerprint: strings.TrimSpace(metadata[model.MetadataDatasourceURLHostFingerprint]),
		}
	}

	rawURL := strings.TrimSpace(metadata[model.MetadataDatasourceURL])
	if rawURL == "" {
		rawURL = strings.TrimSpace(metadata["url"])
	}
	if rawURL == "" {
		return datasourceEndpointInfo{}
	}
	info := datasourceEndpointInfo{Configured: true}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return info
	}
	info.Valid = true
	info.Scheme = strings.ToLower(parsed.Scheme)
	info.Host = normalizeDatasourceHost(parsed.Hostname())
	info.HostFingerprint = datasourceHostFingerprint(info.Host)
	if isInternalDatasourceHost(info.Host) {
		info.HostScope = "internal"
	} else {
		info.HostScope = "public"
	}
	return info
}

func datasourceHostFingerprint(host string) string {
	host = normalizeDatasourceHost(host)
	if host == "" {
		return ""
	}
	return model.StableID("datasource-host", host)
}

func normalizeDatasourceHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func datasourceHostSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values)*2)
	for _, value := range values {
		host := normalizeDatasourceHost(value)
		if host == "" {
			continue
		}
		result[host] = true
		result[datasourceHostFingerprint(host)] = true
	}
	return result
}

func datasourceEndpointAllowed(info datasourceEndpointInfo, allowed map[string]bool) bool {
	return allowed[info.Host] || allowed[info.HostFingerprint]
}

func isInternalDatasourceHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsPrivate() ||
			addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() ||
			addr.IsMulticast() ||
			addr.IsUnspecified()
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".internal", ".svc", ".svc.cluster.local", ".cluster.local"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
