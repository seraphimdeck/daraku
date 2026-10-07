package parser

import (
	"testing"
)

func TestParseSID(t *testing.T) {
	validSIDBytes := []byte{
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // Header + Authority
		0x20, 0x00, 0x00, 0x00, // 32 (Little Endian)
		0x20, 0x02, 0x00, 0x00, // 544 (Little Endian)
	}

	tests := []struct {
		name        string
		data        []byte
		offset      int
		expectErr   bool
		expectedStr string
	}{
		{
			name:        "Valid SID S-1-5-32-544",
			data:        validSIDBytes,
			offset:      0,
			expectErr:   false,
			expectedStr: "S-1-5-32-544",
		},
		{
			name:      "Data terlalu pendek untuk header",
			data:      []byte{0x01, 0x02, 0x00, 0x00}, // Kurang dari 8 bytes
			offset:    0,
			expectErr: true,
		},
		{
			name:      "SubAuthorityCount melebihi batas spesifikasi ( > 15 )",
			data:      []byte{0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}, // 0x10 = 16
			offset:    0,
			expectErr: true,
		},
		{
			name:      "Data terlalu pendek untuk membaca SubAuthority",
			data:      []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00}, // Terpotong
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := ParseSID(tt.data, tt.offset)
			
			if tt.expectErr {
				if err == nil {
					t.Errorf("Diharapkan error, tetapi mendapatkan hasil sukses")
				}
			} else {
				if err != nil {
					t.Fatalf("Tidak diharapkan error, tetapi mendapatkan: %v", err)
				}
				if sid == nil {
					t.Fatal("Objek SID kembalian adalah nil")
				}
				if sid.String() != tt.expectedStr {
					t.Errorf("Diharapkan string SID %s, tetapi mendapatkan %s", tt.expectedStr, sid.String())
				}
				expectedLen := 8 + int(sid.SubAuthorityCount)*4
				if sid.Len() != expectedLen {
					t.Errorf("Diharapkan Len() %d, tetapi mendapatkan %d", expectedLen, sid.Len())
				}
			}
		})
	}
}
