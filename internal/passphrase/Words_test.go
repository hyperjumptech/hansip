package passphrase

import "testing"

func TestRandomPassphrase(t *testing.T) {
	enGen := NewEnglishPassphraseGenerator()
	for i := 2; i <= 10; i++ {
		w, err := enGen.RandomPassphrase(i, 4)
		if err != nil {
			t.Fail()
		}
		t.Logf("%d : %s", i, w)
	}
}
