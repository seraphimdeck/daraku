package parser

import (
    "encoding/binary"
    "fmt"
)

type SID struct {
    Revision uint8
    SubAuthorityCount uint8
    IdentifierAuthority [6]byte
    SubAuthority []uint32
}

func ParseSID(data []byte, offset int) (*SID, error) {
    if offset+8 > len(data) {
        return nil, fmt.Errorf("data terlalu pendek untuk SID header")
    }

    sid := &SID{
        Revision: data[offset],
        SubAuthorityCount: data[offset+1],
    }

    if sid.SubAuthorityCount > 15 {
		return nil, fmt.Errorf("SubAuthorityCount tidak valid: %d", sid.SubAuthorityCount)
	}

    copy(sid.IdentifierAuthority[:], data[offset+2:offset+8])

    subAuthStart := offset + 8
    subAuthEnd := subAuthStart + int(sid.SubAuthorityCount)*4

    if subAuthEnd > len(data) {
        return nil, fmt.Errorf("data terlalu pendek untuk SID sub-authorities")
    }

    sid.SubAuthority = make([]uint32, sid.SubAuthorityCount)
    for i := 0; i < int(sid.SubAuthorityCount); i++ {
        sid.SubAuthority[i] = binary.LittleEndian.Uint32(data[subAuthStart+i*4:])
    }

    return sid, nil
}

func (s *SID) Len() int {
    return 8 + int(s.SubAuthorityCount)*4
}

func (s *SID) String() string {
    auth := uint64(0)
    for _, b := range s.IdentifierAuthority {
        auth = auth<<8 | uint64(b)
    }

    result := fmt.Sprintf("S-%d-%d", s.Revision, auth)
    for _, sub := range s.SubAuthority {
        result += fmt.Sprintf("-%d", sub)
    }
    return result
}