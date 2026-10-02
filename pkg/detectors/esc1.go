package detectors

import (
	"fmt"
	"github.com/seraphimdeck/daraku/pkg/models"
)

const (
	OIDClientAuth       = "1.3.6.1.5.5.7.3.2"
	OIDPKINITClientAuth = "1.3.6.1.5.2.3.4"
	OIDSmartcardLogon   = "1.3.6.1.4.1.311.20.2.2"
	OIDAnyPurpose       = "2.5.29.37.0"
)

func (e *Engine) DetectESC1() []models.Finding {
	var findings []models.Finding

	for _, tmpl := range e.Templates {
		if tmpl.RequiresManagerApproval {
			continue
		}

		hasClientAuth := false
		hasAnyPurpose := len(tmpl.EKUs) == 0

		for _, eku := range tmpl.EKUs {
			if eku == OIDClientAuth || eku == OIDPKINITClientAuth || eku == OIDSmartcardLogon {
				hasClientAuth = true
			}
			if eku == OIDAnyPurpose {
				hasAnyPurpose = true
			}
		}

		if tmpl.EnrolleeSuppliesSubject && (hasClientAuth || hasAnyPurpose) {
			findings = append(findings, models.Finding{
				ID:             "ESC1",
				Title:          "AD CS Template Misconfiguration - Enrollee Supplies Subject (ESC1)",
				Severity:       models.SeverityCritical,
				Confidence:     models.ConfidenceCandidate,
				Category:       "AD CS",
				AffectedEntity: tmpl.Name,
				Description:    fmt.Sprintf("Template '%s' mengizinkan Subject Alternative Name (SAN) dan EKU untuk otentikasi klien tanpa persetujuan.", tmpl.DisplayName),
				Evidence:       []string{"Enrollee supplies subject", "Manager approval tidak diwajibkan", "Client Authentication/PKINIT/Smartcard Logon atau Any Purpose EKU terdeteksi"},
				Remediation:    "Hapus centang 'Supply in the request' pada tab Subject Name di MMC Certificate Templates, atau aktifkan 'Require manager approval'.",
				References:     []string{"https://posts.specterops.io/certified-pre-owned-d959109652fb"},
			})
		}
	}

	return findings
}