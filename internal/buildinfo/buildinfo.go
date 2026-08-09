package buildinfo

import "runtime"

const ContractVersion = "build-info.v1"

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	ContractVersion string `json:"contract_version"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuildDate       string `json:"build_date"`
	GoVersion       string `json:"go_version"`
	OS              string `json:"os"`
	Architecture    string `json:"architecture"`
}

func Current() Info {
	return Info{
		ContractVersion: ContractVersion,
		Version:         valueOrDefault(Version, "dev"),
		Commit:          valueOrDefault(Commit, "unknown"),
		BuildDate:       valueOrDefault(BuildDate, "unknown"),
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Architecture:    runtime.GOARCH,
	}
}

func valueOrDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
