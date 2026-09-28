package detectors

import (
    "fmt"
    "github.com/seraphimdeck/serAD/pkg/models"
)

func (e *Engine) DetectAdminCount() []models.Finding {
    var findings []models.Finding

    for _, user := range e.Users {
        if !user.Enabled {
            continue
        }

        if user.AdminCount == 1 && len(user.ServicePrincipalName) > 0 {
            findings = append(findings, models.Finding{
                ID:             "ADMINCOUNT_KERBEROASTABLE",
                Title:          "Privileged Account with SPN (AdminCount=1 Kerberoastable)",
                Severity:       models.SeverityCritical,
                Confidence:     models.ConfidenceConfirmed,
                Category:       "Privilege",
                AffectedEntity: user.SAMAccountName,
                Description:    fmt.Sprintf("Akun privileged '%s' memiliki AdminCount=1 dan SPN terdaftar, rentan Kerberoasting.", user.SAMAccountName),
                Evidence:       []string{fmt.Sprintf("adminCount=1, servicePrincipalName=%v", user.ServicePrincipalName)},
                Remediation:    "Gunakan gMSA untuk service account privileged, atau hapus SPN yang tidak diperlukan.",
                References:     []string{"https://adsecurity.org/?p=2293"},
            })
        }

        if user.AdminCount == 1 && user.DontReqPreauth {
            findings = append(findings, models.Finding{
                ID:             "ADMINCOUNT_ASREP",
                Title:          "Privileged Account with Pre-Auth Disabled (AdminCount=1 AS-REP Roastable)",
                Severity:       models.SeverityCritical,
                Confidence:     models.ConfidenceConfirmed,
                Category:       "Privilege",
                AffectedEntity: user.SAMAccountName,
                Description:    fmt.Sprintf("Akun privileged '%s' memiliki AdminCount=1 dan Kerberos pre-authentication dinonaktifkan.", user.SAMAccountName),
                Evidence:       []string{"adminCount=1, DONT_REQUIRE_PREAUTH flag is enabled"},
                Remediation:    "Aktifkan kembali Kerberos pre-authentication pada akun.",
                References:     []string{"https://adsecurity.org/?p=3513"},
            })
        }
    }

    return findings
}