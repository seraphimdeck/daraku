package parser

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
)

const (
	OBJECT_INHERIT_ACE = 0x01
	CONTAINER_INHERIT_ACE = 0x02
	NO_PROPAGATE_INHERIT_ACE = 0x04
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
)

const (
	ACE_OBJECT_TYPE_PRESENT = 0x1
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
)

const (
	RIGHT_WRITE_DACL = 0x00040000
	RIGHT_WRITE_OWNER = 0x00080000
	RIGHT_GENERIC_WRITE = 0x40000000
	RIGHT_GENERIC_ALL = 0x10000000
	RIGHT_DS_WRITE_PROP = 0x00000020
	RIGHT_DS_WRITE_ALL_PROP = 0x00000010
	RIGHT_DS_CONTROL_ACCESS = 0x00000100
	RIGHT_DS_CREATE_CHILD = 0x00000001
	RIGHT_DS_DELETE_CHILD = 0x00000002
)

const (
	GUIDManageCA = "7911c0fc-6034-11d3-a6da-00a0c91efb8b"
	GUIDManageCertificates = "a05b8cc2-17bc-11d3-a6e6-00a0c91efb8b"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func ParseGUID(data []byte, offset int) (*GUID, error) {
	if offset+16 > len(data) {
		return nil, fmt.Errorf("data terlalu pendek untuk GUID")
	}
	return &GUID{
		Data1: binary.LittleEndian.Uint32(data[offset:]),
		Data2: binary.LittleEndian.Uint16(data[offset+4:]),
		Data3: binary.LittleEndian.Uint16(data[offset+6:]),
		Data4: [8]byte(data[offset+8 : offset+16]),
	}, nil
}

func (g *GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4],
		g.Data4[5], g.Data4[6], g.Data4[7])
}

type ACE struct {
	Type uint8
	Flags uint8
	Size uint16
	AccessMask uint32
	ObjectType *GUID
	InheritedObjType *GUID
	SID *SID
}

func ParseACE(data []byte, offset int) (*ACE, error) {
	if offset+8 > len(data) {
		return nil, fmt.Errorf("data terlalu pendek untuk ACE header")
	}

	ace := &ACE{
		Type: data[offset],
		Flags: data[offset+1],
		Size: binary.LittleEndian.Uint16(data[offset+2:]),
	}

	ace.AccessMask = binary.LittleEndian.Uint32(data[offset+4:])

	sidOffset := offset + 8

	if ace.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
		ace.Type == ACCESS_DENIED_OBJECT_ACE_TYPE {

		if offset+12 > len(data) {
			return nil, fmt.Errorf("data terlalu pendek untuk object ACE flags")
		}

		objectFlags := binary.LittleEndian.Uint32(data[offset+8:])
		sidOffset = offset + 12

		if objectFlags&ACE_OBJECT_TYPE_PRESENT != 0 {
			if sidOffset+16 > len(data) {
				return nil, fmt.Errorf("data terlalu pendek untuk ObjectType GUID")
			}
			guid, err := ParseGUID(data, sidOffset)
			if err != nil {
				return nil, fmt.Errorf("gagal parse ObjectType GUID: %w", err)
			}
			ace.ObjectType = guid
			sidOffset += 16
		}

		if objectFlags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			if sidOffset+16 > len(data) {
				return nil, fmt.Errorf("data terlalu pendek untuk InheritedObjectType GUID")
			}
			guid, err := ParseGUID(data, sidOffset)
			if err != nil {
				return nil, fmt.Errorf("gagal parse InheritedObjectType GUID: %w", err)
			}
			ace.InheritedObjType = guid
			sidOffset += 16
		}
	}

	sid, err := ParseSID(data, sidOffset)
	if err != nil {
		return nil, fmt.Errorf("gagal parse SID di ACE: %w", err)
	}
	ace.SID = sid

	return ace, nil
}

func IsWellKnownAdminSID(sidString string) bool {
	if strings.HasSuffix(sidString, "-512") ||
		strings.HasSuffix(sidString, "-519") ||
		strings.HasSuffix(sidString, "-500") ||
		sidString == "S-1-5-18" ||
		sidString == "S-1-5-32-544" {
		return true
	}
	return false
}

func (a *ACE) EvaluateVulnerability(targetSID string) (isESC4 bool, isESC7 bool) {
	if a.Type != ACCESS_ALLOWED_ACE_TYPE &&
		a.Type != ACCESS_ALLOWED_OBJECT_ACE_TYPE {
		return false, false
	}

	if IsWellKnownAdminSID(targetSID) {
		return false, false
	}

	if a.AccessMask&RIGHT_WRITE_DACL != 0 ||
		a.AccessMask&RIGHT_WRITE_OWNER != 0 ||
		a.AccessMask&RIGHT_GENERIC_WRITE != 0 ||
		a.AccessMask&RIGHT_GENERIC_ALL != 0 ||
		a.AccessMask&RIGHT_DS_WRITE_ALL_PROP != 0 {
		isESC4 = true
	}

	if a.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE && a.ObjectType == nil {
		if a.AccessMask&RIGHT_DS_WRITE_PROP != 0 {
			isESC4 = true
		}
	}

	if a.AccessMask&RIGHT_DS_CONTROL_ACCESS != 0 {
		if a.Type == ACCESS_ALLOWED_ACE_TYPE ||
			(a.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE && a.ObjectType == nil) {
			isESC7 = true
		}
		if a.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE && a.ObjectType != nil {
			guidStr := a.ObjectType.String()
			if guidStr == GUIDManageCA || guidStr == GUIDManageCertificates {
				isESC7 = true
			}
		}
	}

	return isESC4, isESC7
}