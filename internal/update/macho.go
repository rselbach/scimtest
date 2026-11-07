package update

import "encoding/binary"

const cpuTypeARM64 = 0x0100000c

// machOHasARM64 reports whether a Mach-O header, thin or universal, lists an
// arm64 slice.
func machOHasARM64(head []byte) bool {
	if len(head) < 8 {
		return false
	}
	switch binary.BigEndian.Uint32(head) {
	case 0xcffaedfe: // MH_MAGIC_64 stored little-endian
		return binary.LittleEndian.Uint32(head[4:]) == cpuTypeARM64
	case 0xcafebabe, 0xcafebabf: // FAT_MAGIC and FAT_MAGIC_64, big-endian
		stride := 20
		if binary.BigEndian.Uint32(head) == 0xcafebabf {
			stride = 32
		}
		count := min(int(binary.BigEndian.Uint32(head[4:])), 16)
		for i := range count {
			at := 8 + i*stride
			if at+4 > len(head) {
				return false
			}
			if binary.BigEndian.Uint32(head[at:]) == cpuTypeARM64 {
				return true
			}
		}
	}
	return false
}
