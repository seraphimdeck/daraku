package parser

import (
	"encoding/binary"
	"fmt"
)

const (
	SE_DACL_PRESENT = 0x0004
	SE_DACL_AUTO_INHERITED = 0x0400
)

type SecurityDescriptor struct {
	Revision uint8
	Control  uint16
	ACEs     []*ACE
}

func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data terlalu pendek untuk Security Descriptor header")
	}

	sd := &SecurityDescriptor{
		Revision: data[0],
		Control:  binary.LittleEndian.Uint16(data[2:]),
	}

	if sd.Control&SE_DACL_PRESENT == 0 {
		return sd, nil
	}

	daclOffset := binary.LittleEndian.Uint32(data[16:])

	if daclOffset == 0 || int(daclOffset) >= len(data) {
		return sd, nil
	}

	if int(daclOffset)+8 > len(data) {
		return nil, fmt.Errorf("data terlalu pendek untuk DACL header")
	}

	aclSize := binary.LittleEndian.Uint16(data[daclOffset+2:])
	aceCount := binary.LittleEndian.Uint16(data[daclOffset+4:])

	if int(daclOffset)+int(aclSize) > len(data) {
		return nil, fmt.Errorf("DACL aclSize melebihi batas buffer data")
	}

	aceOffset := int(daclOffset) + 8

	for i := 0; i < int(aceCount); i++ {
		if aceOffset+4 > len(data) {
			break
		}

		aceSize := binary.LittleEndian.Uint16(data[aceOffset+2:])
		if aceSize < 4 || aceOffset+int(aceSize) > len(data) {
			break
		}

		ace, err := ParseACE(data, aceOffset)
		if err != nil {
			break
		}

		sd.ACEs = append(sd.ACEs, ace)
		aceOffset += int(aceSize)
	}

	return sd, nil
}

func (sd *SecurityDescriptor) GetESC4ACEs() []*ACE {
	var result []*ACE

	for _, ace := range sd.ACEs {
		if ace.SID == nil {
			continue
		}
		sidStr := ace.SID.String()
		isESC4, _ := ace.EvaluateVulnerability(sidStr)
		if isESC4 {
			result = append(result, ace)
		}
	}

	return result
}

func (sd *SecurityDescriptor) GetESC7ACEs() []*ACE {
	var result []*ACE

	for _, ace := range sd.ACEs {
		if ace.SID == nil {
			continue
		}
		sidStr := ace.SID.String()
		_, isESC7 := ace.EvaluateVulnerability(sidStr)
		if isESC7 {
			result = append(result, ace)
		}
	}

	return result
}