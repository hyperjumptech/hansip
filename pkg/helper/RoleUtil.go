package helper

import (
	"fmt"
	"regexp"
	"strings"
)

// IsRoleValid ini melakukan validasi apakah Role-Role yang menjadi syarat
// untuk mengakses sebuah resourse (requires) bisa dipenuhi oleh seorang pengakses
// yang memiliki Role-Role tertentu (supplied).
//
// Sebagai contoh :
//
// Diketahui sebuah path "/artikel/abc" dari URL "https://domain.com/artikel/abc"
// Path ini mewajibkan pengakses harus memiliki role "user@domain.com" dan juga harus memiliki role "reader@domain.com".
//
// Jika pengakses path tersebut, miliki role (bisa di ambil dari database, atau dari token) sebagai berikut.
// "user@domain.com" dan "writer@domain.com"
//
// Maka fungsi IsRoleValid ini bisa dipergunakan apakah pengakses tersebut boleh mengakses path dimaksud.
//
// Allowed := IsRoleValid([]string {"user@domain.com","reader@domain.com"}, []string {"user@domain.com", "writer@domain.com"})
//
// Allowed adalah nilai boolean, dimana apabila nilainya TRUE maka user boleh mengakses. dan FALSE jika tidak.
// Silahkan lihat testing code dibagian bawah.
//
// Baik requires dan supplied keduanya berisi array string. Dimana requires semuanya WAJIB dipenuhi oleh supplied.
// Jika salah satu role yang disebutkan dalam requires tidak dipenuhi, maka IsRoleValid akan mengembalikan FALSE.
//
// Contoh 1 :
//     requires = []string {"user@domain.com", "reader@domain.com"}
//
// Maka IsRoleValid akan mengembalikan nilai TRUE jika :
//
//  1. supplied = []string {"user@domain.com", "reader@domain.com"} // pengakses memiliki role yang diperlukan.
//  2. supplied = []string {"*@domain.com"} // pengakses memiliki role yang secara pola/pattern memenuhi semua syarat role dalam requires.
//  3. supplied = []string {"*@domain.com", "abc@other.com"} // pengakses memiliki role yang salah satunya, secara pola/pattern, memenuhi semua syarat role dalam requires.
//
// Contoh 2 :
//      requires = []string {"*@domain.com"}
//
// Maka IsRoleValid akan mengembalikan nilai TRUE jika :
//
//  1. supplied = []string {"user@domain.com"} // pengakses memiliki role yang memenuhi pola syarat role dalam requires.
//  2. supplied = []string {"user@domain.com", "abc@other.com"} // pengakses memiliki role yang salah satunya memenuhi pola syarat role dalam requires.
//
// CATATAN : requires yang memiliki role dengan pola wildcard, tidak bisa dipenuhi dengan supplied yang juga menggunakan pola wildcard.
//           Contoh :
//
// NeverAllowed := IsRoleValid([]string {"*@domain.com"}, []string {"writer@*"});
//
// Silahkan lihat contoh testing di RoleUtil_test.go
func IsRoleValid(requires, supplied []string) bool {
	if len(requires) == 0 {
		return true
	}
	valid := false
	for _, require := range requires {
		requireValid := false
		for _, supply := range supplied {
			if matchesTwoRole(require, supply) {
				valid = true
				requireValid = true
			}
		}
		if !requireValid {
			return false
		}
	}
	return valid
}

// matchesTwoRole ini adalah fungsi sederhana yang dipergunakan oleh fungsi IsRoleValid
// untuk membandingkan apakah diantara 2 string bisa saling memenuhi pola role diantara mereka.
//
// Contoh :
//  Jika a := "abcd@efghijk.lmn.com"
//
// Maka fungsi MatchesTwoRole akan mengembalikan nilai TRUE jika:
//  1. b := "abcd@efghijk.lmn.com" // dimana b sama persis dengan a.
//  2. b := "*@efghijk.lmn.com" // dimana b memiliki pola yang cocok dengan a.
//  3. b := "*@*" // b memiliki pola yang cocok dengan a (variasi pola)
//  4. b := "*cd@efghijk.*" // b memiliki pola yang cocok dengan a (variasi pola)
func matchesTwoRole(a, b string) bool {
	aw := strings.Contains(a, "*")
	bw := strings.Contains(b, "*")
	if aw && bw {
		return false
	}
	if !aw && !bw {
		return a == b
	}
	if aw {
		rx, err := regexp.Compile(fmt.Sprintf("^%s$", strings.ReplaceAll(a, "*", `[a-zA-Z0-9_\-\.]+`)))
		if err != nil {
			return false
		}
		return rx.Match([]byte(b))
	}
	if bw {
		rx, err := regexp.Compile(fmt.Sprintf("^%s$", strings.ReplaceAll(b, "*", `[a-zA-Z0-9_\-\.]+`)))
		if err != nil {
			return false
		}
		return rx.Match([]byte(a))
	}
	return false
}
