package buildinfo

import "testing"

func TestCurrentReturnsBoundedBuildIdentity(t *testing.T) {
	previousVersion, previousCommit, previousDate := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = previousVersion, previousCommit, previousDate })
	Version, Commit, BuildDate = "", "", ""

	info := Current()
	if info.ContractVersion != "build-info.v1" || info.Version != "dev" || info.Commit != "unknown" || info.BuildDate != "unknown" || info.GoVersion == "" || info.OS == "" || info.Architecture == "" {
		t.Fatalf("unexpected build info: %#v", info)
	}
}
