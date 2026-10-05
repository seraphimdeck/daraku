package parser

import (
	"testing"
)

func TestParseSecurityDescriptor(t *testing.T) {
	// Konstruksi byte manual untuk Security Descriptor dengan DACL kosong.
	// Header SD: Revision(1), Sbz1(1), Control(2), OffsetOwner(4), OffsetGroup(4), OffsetSacl(4), OffsetDacl(4)
	validSDBytes := []byte{
		0x01, 0x00, 0x04, 0x00, // Revision, Sbz1, Control (SE_DACL_PRESENT = 0x0004)
		0x00, 0x00, 0x00, 0x00, // OffsetOwner
		0x00, 0x00, 0x00, 0x00, // OffsetGroup
		0x00, 0x00, 0x00, 0x00, // OffsetSacl
		0x14, 0x00, 0x00, 0x00, // OffsetDacl (20 bytes dari awal)
		
		// DACL (berada tepat di offset 20)
		0x02, 0x00, 0x08, 0x00, // AclRevision(2), Sbz1(0), AclSize(8 bytes)
		0x00, 0x00, 0x00, 0x00, // AceCount(0), Sbz2(0)
	}

	tests := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{
			name:      "Valid Security Descriptor (Empty DACL)",
			data:      validSDBytes,
			expectErr: false,
		},
		{
			name:      "Header kurang dari 20 bytes",
			data:      []byte{0x01, 0x00, 0x04, 0x00, 0x00}, // Jelas invalid
			expectErr: true,
		},
		{
			name: "DACL Offset melebihi batas buffer",
			data: []byte{
				0x01, 0x00, 0x04, 0x00, 
				0x00, 0x00, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00, 
				0x99, 0x99, 0x00, 0x00, // OffsetDacl sangat besar
			},
			expectErr: false, // Berdasarkan logika program, jika offset > len(data), SD tetap di-return dengan ACE kosong tanpa error.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := ParseSecurityDescriptor(tt.data)
			
			if tt.expectErr {
				if err == nil {
					t.Errorf("Diharapkan error, tetapi mendapatkan hasil sukses")
				}
			} else {
				if err != nil {
					t.Fatalf("Tidak diharapkan error, tetapi mendapatkan: %v", err)
				}
				if sd == nil {
					t.Fatal("Objek Security Descriptor kembalian adalah nil")
				}
			}
		})
	}
}
