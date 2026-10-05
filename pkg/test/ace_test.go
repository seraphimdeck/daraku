package parser

import (
	"testing"
)

func TestIsWellKnownAdminSID(t *testing.T) {
	tests := []struct {
		sid      string
		expected bool
	}{
		{"S-1-5-21-12345-512", true}, // Domain Admins
		{"S-1-5-21-12345-519", true}, // Enterprise Admins
		{"S-1-5-32-544", true},       // Builtin Administrators
		{"S-1-5-18", true},           // Local System
		{"S-1-5-21-12345-1001", false}, // Normal User
	}

	for _, tt := range tests {
		t.Run(tt.sid, func(t *testing.T) {
			if got := IsWellKnownAdminSID(tt.sid); got != tt.expected {
				t.Errorf("IsWellKnownAdminSID(%s) = %v, want %v", tt.sid, got, tt.expected)
			}
		})
	}
}

func TestEvaluateVulnerability(t *testing.T) {
	// Membuat GUID tiruan untuk ManageCA
	manageCAGUID := &GUID{
		Data1: 0x7911c0fc, Data2: 0x6034, Data3: 0x11d3,
		Data4: [8]byte{0xa6, 0xda, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b},
	}

	tests := []struct {
		name       string
		ace        *ACE
		targetSID  string
		wantESC4   bool
		wantESC7   bool
	}{
		{
			name: "Well-known Admin diabaikan",
			ace: &ACE{
				Type:       ACCESS_ALLOWED_ACE_TYPE,
				AccessMask: RIGHT_GENERIC_ALL,
			},
			targetSID: "S-1-5-21-123-512", // Domain Admin
			wantESC4:  false,
			wantESC7:  false,
		},
		{
			name: "Non-Admin punya WriteDACL (ESC4)",
			ace: &ACE{
				Type:       ACCESS_ALLOWED_ACE_TYPE,
				AccessMask: RIGHT_WRITE_DACL,
			},
			targetSID: "S-1-5-21-123-1001", // Normal User
			wantESC4:  true,
			wantESC7:  false,
		},
		{
			name: "Access Denied ACE dilewati",
			ace: &ACE{
				Type:       ACCESS_DENIED_ACE_TYPE,
				AccessMask: RIGHT_GENERIC_ALL,
			},
			targetSID: "S-1-5-21-123-1001",
			wantESC4:  false,
			wantESC7:  false,
		},
		{
			name: "Non-Admin punya Control Access dengan GUID ManageCA (ESC7)",
			ace: &ACE{
				Type:       ACCESS_ALLOWED_OBJECT_ACE_TYPE,
				AccessMask: RIGHT_DS_CONTROL_ACCESS,
				ObjectType: manageCAGUID,
			},
			targetSID: "S-1-5-21-123-1001",
			wantESC4:  false,
			wantESC7:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotESC4, gotESC7 := tt.ace.EvaluateVulnerability(tt.targetSID)
			if gotESC4 != tt.wantESC4 {
				t.Errorf("EvaluateVulnerability() gotESC4 = %v, want %v", gotESC4, tt.wantESC4)
			}
			if gotESC7 != tt.wantESC7 {
				t.Errorf("EvaluateVulnerability() gotESC7 = %v, want %v", gotESC7, tt.wantESC7)
			}
		})
	}
}
