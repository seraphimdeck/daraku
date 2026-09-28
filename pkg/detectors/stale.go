package detectors

import (
    "fmt"
    "time"
    "github.com/seraphimdeck/serAD/pkg/models"
)

func (e *Engine) DetectStaleObjects() []models.Finding {
    var findings []models.Finding
    threshold := time.Now().AddDate(0, 0, -90)

    for _, user := range e.Users {
        if !user.Enabled {
            continue
        }

        if !user.LastLogon.IsZero() && user.LastLogon.Before(threshold) {
            findings = append(findings, models.Finding{
                ID:             "STALE_USER",
                Title:          "Active User Account with No Recent Logon (Stale)",
                Severity:       models.SeverityMedium,
                Confidence:     models.ConfidenceConfirmed,
                Category:       "Hygiene",
                AffectedEntity: user.SAMAccountName,
                Description:    fmt.Sprintf("Akun '%s' masih aktif tetapi tidak login sejak %s.", user.SAMAccountName, user.LastLogon.Format("2006-01-02")),
                Evidence:       []string{fmt.Sprintf("lastLogon=%s", user.LastLogon.Format("2006-01-02"))},
                Remediation:    "Nonaktifkan atau hapus akun yang tidak aktif lebih dari 90 hari.",
                References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
            })
        }
    }

    for _, comp := range e.Computers {
        if !comp.Enabled {
            continue
        }

        if !comp.LastLogon.IsZero() && comp.LastLogon.Before(threshold) {
            findings = append(findings, models.Finding{
                ID:             "STALE_COMPUTER",
                Title:          "Active Computer Object with No Recent Logon (Stale)",
                Severity:       models.SeverityLow,
                Confidence:     models.ConfidenceConfirmed,
                Category:       "Hygiene",
                AffectedEntity: comp.SAMAccountName,
                Description:    fmt.Sprintf("Computer object '%s' masih aktif tetapi tidak login sejak %s.", comp.SAMAccountName, comp.LastLogon.Format("2006-01-02")),
                Evidence:       []string{fmt.Sprintf("lastLogon=%s", comp.LastLogon.Format("2006-01-02"))},
                Remediation:    "Nonaktifkan atau hapus computer object yang tidak aktif lebih dari 90 hari.",
                References:     []string{"https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"},
            })
        }
    }

    return findings
}