package helper

func StringToIntHash(txt string) int {
	primes := []int{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251}
	slot := []int{0b01010101, 0b11001100, 0b10101010, 0b00110011, 0b01010101, 0b11001100, 0b10101010}
	for i, b := range []byte(txt) {
		p := primes[int(b)%len(primes)]
		iof := i % 7
		slot[iof] = slot[iof] ^ p
	}
	ret := 0
	for i, _ := range slot {
		if i > 0 {
			slot[i] = slot[i] << (i * 8)
		}
		ret = ret | slot[i]
	}
	return ret
}

// StringArrayContainString returns true if the array contains specified string.
func StringArrayContainString(array []string, s string) bool {
	for _, v := range array {
		if v == s {
			return true
		}
	}
	return false
}
