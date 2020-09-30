package passphrase

import "testing"

type TestPassphrase struct {
	Pass        string
	MinChar     int
	MinWord     int
	MinCharWord int
	Valid       bool
}

var (
	testData = []TestPassphrase{
		{"thisisaverylongpass", 10, 1, 1, true},
		{"shortpass", 10, 1, 1, false},
		{"shortpass", 3, 2, 1, false},
		{"short pass", 3, 2, 1, true},
		{"short pass right", 3, 2, 1, true},
		{"short pass good", 3, 2, 4, true},
		{"short pass is good", 3, 2, 4, false},
	}
)

func TestValidate(t *testing.T) {
	for i, td := range testData {
		if Validate(td.Pass, td.MinChar, td.MinWord, td.MinCharWord) != td.Valid {
			t.Logf("Test data %d expect %s is minchar %d, minword %d, mincharinword %d to be %v but %v", i, td.Pass, td.MinChar, td.MinWord, td.MinCharWord, td.Valid, Validate(td.Pass, td.MinChar, td.MinWord, td.MinCharWord))
			t.Fail()
		}
	}
}
