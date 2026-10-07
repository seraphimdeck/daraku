package detectors

import (
	"testing"
	"github.com/seraphimdeck/daraku/pkg/models"
)

func TestDetectAdminCount(t *testing.T) {
	mockUsers := []models.User{
		{
			SAMAccountName:       "Admin_Kerberoastable",
			Enabled:              true,
			AdminCount:           1,
			ServicePrincipalName: []string{"MSSQLSvc/db01.corp.local:1433"},
			DontReqPreauth:       false,
		},
		{
			SAMAccountName:       "Admin_ASREP",
			Enabled:              true,
			AdminCount:           1,
			ServicePrincipalName: nil,
			DontReqPreauth:       true,
		},
		{
			SAMAccountName:       "Safe_Domain_Admin",
			Enabled:              true,
			AdminCount:           1,
			ServicePrincipalName: nil,
			DontReqPreauth:       false,
		},
		{
			SAMAccountName:       "Disabled_Admin",
			Enabled:              false,
			AdminCount:           1,
			DontReqPreauth:       true,
		},
	}

	engine := NewEngine(mockUsers, nil, nil, nil)
	findings := engine.DetectAdminCount()

	if len(findings) != 2 {
		t.Fatalf("mendapatkan %d", len(findings))
	}

	foundKerberoast := false
	foundASREP := false

	for _, f := range findings {
		if f.ID == "ADMINCOUNT_KERBEROASTABLE" && f.AffectedEntity == "Admin_Kerberoastable" {
			foundKerberoast = true
		}
		if f.ID == "ADMINCOUNT_ASREP" && f.AffectedEntity == "Admin_ASREP" {
			foundASREP = true
		}
	}

	if !foundKerberoast {
		t.Errorf("Gagal mendeteksi ADMINCOUNT_KERBEROASTABLE pada user yang valid")
	}
	if !foundASREP {
		t.Errorf("Gagal mendeteksi ADMINCOUNT_ASREP pada user yang valid")
	}
}

func TestDetectASREP(t *testing.T) {
	mockUsers := []models.User{
		{
			SAMAccountName: "User_ASREP_Roastable",
			Enabled:        true,
			AdminCount:     0,
			DontReqPreauth: true,
		},
		{
			SAMAccountName: "User_Safe",
			Enabled:        true,
			AdminCount:     0,
			DontReqPreauth: false,
		},
	}

	engine := NewEngine(mockUsers, nil, nil, nil)
	findings := engine.DetectASREP()

	if len(findings) != 1 {
		t.Fatalf("mendapatkan %d", len(findings))
	}

	if findings[0].ID != "ASREP_ROAST" || findings[0].AffectedEntity != "User_ASREP_Roastable" {
		t.Errorf("Error: %s", findings[0].AffectedEntity)
	}
}
