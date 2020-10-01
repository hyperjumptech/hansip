package helper

// StringToIntHash will create an uint64 hash out of a string.
// For example :
// - "a" -> 0xC1
// - "aa" -> 0xC1C1
// - "aaa" -> 0xC1C1C1
// - "aaaaaaaa" -> 0xC1C1C1C1C1C1C1C1
// - "aaaaaaaaa" -> 0xC1C1C1C1C1C1C100
// - "aaaaaaaaaa" -> 0xC1C1C1C1C1C10000
// - "a quick brown fox jumps over lazy dogs" -> 0x28CA548533F78701
func StringToIntHash(txt string) uint64 {
	slots := 8

	// primes is array of prime numbers between 0 to 255. Its used to xor the byte portion of uint64 result.
	primes := []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251}

	// slot is the binary representation of our uint64 result. The value presented here is just the initial flavour.
	// 0         1         2         3         4         5         6
	// 0123456789012345678901234567890123456789012345678901234567890123
	// <slot 1><slot 2><slot 3><slot 4><slot 5><slot 6><slot 7><slot 8>

	slot := make([]uint64, slots)

	// for each byte character in the txt
	// we going to select the prime number based on the character byte and xor them with the designated slot.
	//
	// txt[n].prime,   txt[n+8].prime  will xor slot-1
	// txt[n+1].prime, txt[n+9].prime  will xor slot-2
	// txt[n+2].prime, txt[n+10].prime will xor slot-3
	// txt[n+3].prime, txt[n+11].prime will xor slot-4
	// txt[n+4].prime, txt[n+12].prime will xor slot-5
	// txt[n+5].prime, txt[n+13].prime will xor slot-6
	// txt[n+6].prime, txt[n+14].prime will xor slot-7
	// txt[n+7].prime, txt[n+15].prime will xor slot-8
	//
	for i, b := range []byte(txt) {
		// select the prime number for that byte character from our prime array
		p := primes[int(b)%len(primes)]

		// xor the slot byte with the selected prime.
		iof := i % slots
		slot[iof] = slot[iof] ^ p
	}

	// insert and shift each slot into the final uint64
	ret := uint64(0)
	for i, _ := range slot {
		if i > 0 {
			slot[i] = slot[i] << (i * slots)
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
