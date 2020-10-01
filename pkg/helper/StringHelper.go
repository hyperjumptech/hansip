package helper

import (
	"crypto/md5"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// StringToIntHash will create an int hash out of a string.
//
// captureBit is number of bit to be captured.
//     in 64 bit system, the valid value are between 8 to 64
//     in 32 bit system, the valid value are between 8 to 32
//     note : The higher the captureBit, it'll be more unlikely for two string get the same hash.
//            The lower the captureBit, it'll be more likely for two string to have the same hash.
//     to capture 11 digit integer, 36 bit to be captured.
func StringToIntHash(txt string, captureBit int) int {
	bytes := md5.Sum([]byte(strings.Repeat(txt, 10)))
	rets := 0
	slots := 0
	if strings.Contains(runtime.GOARCH, "64") {
		slots = 8
	} else {
		slots = 4
	}
	slot := make([]byte, slots)
	for i, b := range bytes {
		if i < len(slot) {
			slot[i] = b
		} else {
			slot[i%4] = slot[i%4] ^ b
		}
	}
	bits := captureBit
	if captureBit > (slots * 8) {
		bits = slots * 8
	}
	if captureBit < 8 {
		bits = 8
	}
	bitmap := fmt.Sprintf("%s%s", strings.Repeat("0", (slots*8)-bits), strings.Repeat("1", bits))
	for i := 0; i < slots; i++ {
		inte, err := strconv.ParseInt(bitmap[i*8:(i*8)+8], 2, 64)
		if err != nil {
			panic(err.Error())
		}
		slot[i] = slot[i] & byte(inte)
	}
	for i := 0; i < slots; i++ {
		if i == 0 {
			rets = int(slot[i])
		} else {
			rets = rets << 8
			rets = rets | int(slot[i])
		}
	}
	return rets
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
