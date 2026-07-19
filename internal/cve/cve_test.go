package cve

import (
	"testing"

	"github.com/security-life-org/DarkObscura/internal/fingerprint"
)

func TestCorrelate_MatchesAffectedVersion(t *testing.T) {
	techs := []fingerprint.Tech{
		{Name: "Apache", Version: "2.4.49", Confidence: fingerprint.Confirmed},
		{Name: "nginx", Version: "1.18.0", Confidence: fingerprint.Confirmed},
		{Name: "nginx", Version: "1.25.1", Confidence: fingerprint.Confirmed}, // patched → no match
	}
	v := Correlate(techs)
	var apache, nginxOld, nginxNew bool
	for _, x := range v {
		if x.ID == "CVE-2021-41773" { apache = true }
		if x.ID == "CVE-2021-23017" && x.Version == "1.18.0" { nginxOld = true }
		if x.Version == "1.25.1" { nginxNew = true }
	}
	if !apache { t.Error("expected Apache 2.4.49 → CVE-2021-41773") }
	if !nginxOld { t.Error("expected nginx 1.18.0 → CVE-2021-23017") }
	if nginxNew { t.Error("nginx 1.25.1 is patched; must NOT match") }
}

func TestCorrelate_IgnoresUnconfirmedOrVersionless(t *testing.T) {
	techs := []fingerprint.Tech{
		{Name: "Apache", Version: "2.4.49", Confidence: fingerprint.Likely},   // not confirmed
		{Name: "Drupal", Version: "", Confidence: fingerprint.Confirmed},      // no version
	}
	if v := Correlate(techs); len(v) != 0 {
		t.Errorf("expected zero CVEs for unconfirmed/versionless tech; got %v", v)
	}
}
