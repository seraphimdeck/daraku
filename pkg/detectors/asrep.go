package detectors

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func (e *Engine) DetectASREP() []models.Finding {
	var findings []models.Finding

	for _, user := range e.Users {
		if user.Enabled && user.DontReqPreauth {
			findings = append(findings, models.Finding{
				ID:             "ASREP_ROAST",
				Title:          "Kerberos Pre-Authentication Disabled (AS-REP Roastable)",
				Severity:       models.SeverityHigh,
				Confidence:     models.ConfidenceConfirmed,
				Category:       "Kerberos",
				AffectedEntity: user.SAMAccountName,
				Description:    fmt.Sprintf("Akun pengguna '%s' memiliki flag DONT_REQUIRE_PREAUTH.", user.SAMAccountName),
				Evidence:       []string{"userAccountControl DONT_REQUIRE_PREAUTH flag is enabled"},
				Remediation:    "Nonaktifkan opsi 'Do not require Kerberos preauthentication' pada akun pengguna di Active Directory.",
				References:     []string{"https://adsecurity.org/?p=3513"},
			})
		}
	}

	return findings
}
