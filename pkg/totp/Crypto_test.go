package totp

import (
	"fmt"
	"testing"
	"time"
)

func TestGenerateTOTP(t *testing.T) {
	seed := "3132333435363738393031323334353637383930"
	T0 := 0
	X := 30
	testTime := 59
	T := (testTime - T0) / X
	steps := fmt.Sprintf("%X", T)
	otp, err := GenerateTotp(seed, steps, 8)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(otp)
	}
}

func TestHOTPRFC(t *testing.T) {
	t.Log("Testing HOTP according to RFC 6238 - https://tools.ietf.org/html/rfc6238")
	// Seed for HMAC-SHA1 - 20 bytes
	seed := "3132333435363738393031323334353637383930"
	T0 := 0
	X := 30
	testTime := []int{59, 1111111109, 1111111111,
		1234567890, 2000000000, 20000000000}
	results := []string{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"}
	steps := "0"

	t.Log(
		"+---------------+---------------------------+" +
			"------------------+--------+--------+")
	t.Log(
		"|  Time(sec)    |   Time (UTC format)       " +
			"| Value of T(Hex)  |  TOTP  |")
	t.Log(
		"+---------------+----------------------------+" +
			"------------------+--------+")

	for i := 0; i < len(testTime); i++ {
		T := (testTime[i] - T0) / X
		steps = fmt.Sprintf("%X", T)
		for len(steps) < 16 {
			steps = "0" + steps
		}
		fmtTime := fmt.Sprintf("%d-11s", testTime[i])
		utcTime := time.Unix(int64(testTime[i]), 0).UTC().Format(time.RFC3339)

		row := "|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " | "
		otp, err := GenerateTotp(seed, steps, 8)
		if err != nil {
			t.Fail()
			t.Log(err)
		} else {
			if otp != results[i] {
				t.Errorf("Expect %s but %s", results[i], otp)
				t.Fail()
			}
			row = row + otp + " |"
		}
		t.Log(row)
		t.Log(
			"+---------------+----------------------------+" +
				"------------------+--------+")
	}

}

func TestHexStr2Bytes(t *testing.T) {
	seed := "3132333435363738393031323334353637383930"
	arr, err := hexStr2Bytes(seed)
	if err != nil {
		t.Fail()
	}
	for i, v := range arr {
		fmt.Printf("%d -> %d\n", i, v)
	}
}

func TestGenerateTOTPWithDrift(t *testing.T) {
	testTime := []int{59, 60, 89, 90, 119, 120}
	otpValue := []string{"684457", "054433", "054433", "310122", "310122", "415067"}
	key := "345872466819348578495793"
	for i, tt := range testTime {
		otp, err := GenerateTotpWithDrift(key, time.Unix(int64(tt), 0), 30, 6)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		if otp != otpValue[i] {
			t.Errorf("Expect %s but %s", otpValue[i], otp)
			t.Fail()
		}
	}
}
