package detectors

import (
	"fmt"
	"github.com/seraphimdeck/serAD/pkg/models"
)

func (e *Engine) DetectDelegation() []models.Finding {
	var findings []models.Finding

	for _, comp := range e.Computers {
		if !comp.Enabled {
			continue
		}

		if comp.TrustedForDelegation {
			findings = append(findings, models.Finding{
				ID:             "UNCONSTRAINED_DELEGATION",
				Title:          "Unconstrained Kerberos Delegation Configured",
				Severity:       models.SeverityHigh,
				Confidence:     models.ConfidenceConfirmed,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki konfigurasi Unconstrained Delegation.", comp.SAMAccountName),
				Evidence:       []string{"userAccountControl TRUSTED_FOR_DELEGATION flag is enabled"},
				Remediation:    "Migrasi konfigurasi delegasi ke KCD atau RBCD bila sesuai kebutuhan layanan, tinjau host yang memerlukan unconstrained delegation.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}

		if len(comp.AllowedToDelegateTo) > 0 {
			findings = append(findings, models.Finding{
				ID:             "CONSTRAINED_DELEGATION",
				Title:          "Kerberos Constrained Delegation Configured",
				Severity:       models.SeverityInfo,
				Confidence:     models.ConfidenceObserved,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki daftar target delegasi: %v.", comp.SAMAccountName, comp.AllowedToDelegateTo),
				Evidence:       []string{fmt.Sprintf("msDS-AllowedToDelegateTo=%v", comp.AllowedToDelegateTo)},
				Remediation:    "Tinjau daftar SPN target yang diperlukan untuk didelegasikan.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
			})
		}

		if comp.RBCDConfigured {
			findings = append(findings, models.Finding{
				ID:             "RBCD_CONFIGURED",
				Title:          "Resource-Based Constrained Delegation Configured",
				Severity:       models.SeverityMedium,
				Confidence:     models.ConfidenceObserved,
				Category:       "Delegation",
				AffectedEntity: comp.SAMAccountName,
				Description:    fmt.Sprintf("Komputer/Server '%s' memiliki msDS-AllowedToActOnBehalfOfOtherIdentity.", comp.SAMAccountName),
				Evidence:       []string{"msDS-AllowedToActOnBehalfOfOtherIdentity memiliki nilai"},
				Remediation:    "Tinjau security descriptor RBCD, pastikan computer/service accounts yang memiliki hak delegasi.",
				References:     []string{"https://learn.microsoft.com/en-us/windows-server/security/kerberos/resource-based-constrained-delegation"},
			})
		}
}

  for _, user := range e.Users {
    if !user.Enabled {
        continue
    }

    if user.TrustedForDelegation {
        findings = append(findings, models.Finding{
            ID:             "UNCONSTRAINED_DELEGATION_USER",
            Title:          "User Account with Unconstrained Kerberos Delegation",
            Severity:       models.SeverityCritical,
            Confidence:     models.ConfidenceConfirmed,
            Category:       "Delegation",
            AffectedEntity: user.SAMAccountName,
            Description:    fmt.Sprintf("Akun pengguna '%s' memiliki konfigurasi Unconstrained Delegation.", user.SAMAccountName),
            Evidence:       []string{"userAccountControl TRUSTED_FOR_DELEGATION flag is enabled"},
            Remediation:    "Unconstrained Delegation pada user account berbahaya. Nonaktifkan dan migrasi ke Constrained Delegation atau RBCD.",
            References:     []string{"https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"},
        })
    }

    if len(user.AllowedToDelegateTo) > 0 {
        findings = append(findings, models.Finding{
            ID:             "CONSTRAINED_DELEGATION_USER",
            Title:          "User Account with Constrained Kerberos Delegation",
            Severity:       models.SeverityMedium,
            Confidence:     models.ConfidenceObserved,
            Category:       "Delegation",
            AffectedEntity: user.SAMAccountName,
            Description:    fmt.Sprintf("Akun pengguna '%s' memiliki daftar target delegasi: %v.", user.SAMAccountName, user.AllowedToDelegateTo),
            Evidence:       []string{fmt.Sprintf("msDS-AllowedToDelegateTo=%v", user.AllowedToDelegateTo)},
            Remediation:    "Tinjau daftar SPN target yang didelegasikan, pastikan hanya service account yang memang membutuhkan delegasi.",
            References:     []string{"https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"},
        })
    }

    if user.RBCDConfigured {
        findings = append(findings, models.Finding{
            ID:             "RBCD_CONFIGURED_USER",
            Title:          "User Account with Resource-Based Constrained Delegation",
            Severity:       models.SeverityMedium,
            Confidence:     models.ConfidenceObserved,
            Category:       "Delegation",
            AffectedEntity: user.SAMAccountName,
            Description:    fmt.Sprintf("Akun pengguna '%s' memiliki msDS-AllowedToActOnBehalfOfOtherIdentity.", user.SAMAccountName),
            Evidence:       []string{"msDS-AllowedToActOnBehalfOfOtherIdentity memiliki nilai"},
            Remediation:    "Tinjau security descriptor RBCD pada user account ini.",
            References:     []string{"https://learn.microsoft.com/en-us/windows-server/security/kerberos/resource-based-constrained-delegation"},
        })
    }
}

	return findings
}
