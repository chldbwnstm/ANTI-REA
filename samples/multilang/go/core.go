package protectedcore

const blend uint32 = 0x9e3779b9

func mixHelper(a uint32, b uint32) uint32 {
	x := (a ^ blend) * (b | 1)
	return (x &^ 0xff00) ^ (x >> 7) ^ (b << 11)
}

func Fold(a int32, b int32) int32 {
	x := int32(mixHelper(uint32(a), uint32(b)))
	for i := int32(0); i < 5; i++ {
		if i == 2 {
			continue
		}
		if x < b {
			x += a * (i + 1)
		} else {
			x ^= b - i
		}
	}
	return x
}

func Wide(a int64, count uint64) int64 {
	return (a >> count) ^ (a << uint32(count)) ^ int64(uint64(a)*0xd6e8feb86659fd93)
}

func Mix(a uint32, b uint32) uint64 {
	x := uint64(mixHelper(a, b))
	return x*0x94d049bb133111eb + uint64(int64(int32(b)))
}

func Narrow(a int64, b uint32) uint32 {
	x := int32(a)
	if x >= 0 && b != 0 {
		return uint32(x) ^ b
	}
	return uint32(int64(x) - int64(b))
}
