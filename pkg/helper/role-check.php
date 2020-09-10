<?php

/**
 * IsRoleInvalid ini melakukan validasi apakah Role-Role yang menjadi syarat
 * untuk mengakses sebuah resourse ($requires) bisa dipenuhi oleh seorang pengakses
 * yang memiliki Role-Role tertentu ($supplied).
 *
 * Sebagai contoh :
 *
 * Diketahui sebuah path "/artikel/abc" dari URL "https://domain.com/artikel/abc"
 * Path ini mewajibkan pengakses harus memiliki role "user@domain.com" dan juga harus memiliki role "reader@domain.com".
 *
 * Jika pengakses path tersebut, miliki role (bisa di ambil dari database, atau dari token) sebagai berikut.
 * "user@domain.com" dan "writer@domain.com"
 *
 * Maka fungsi IsRoleValid ini bisa dipergunakan apakah pengakses tersebut boleh mengakses path dimaksud.
 *
 * Allowed = IsRoleValid(array("user@domain.com","reader@domain.com"), array("user@domain.com", "writer@domain.com"));
 *
 * Allowed adalah nilai boolean, dimana apabila nilainya TRUE maka user boleh mengakses. dan FALSE jika tidak.
 * Silahkan lihat testing code dibagian bawah.
 *
 * Baik $required dan $supplied keduanya berisi array string. Dimana $required semuanya WAJIB dipenuhi oleh $supplied.
 * Jika salah satu role yang disebutkan dalam $required tidak dipenuhi, maka IsRoleValid akan mengembalikan FALSE.
 *
 * Contoh 1 :
 *     $required = array("user@domain.com", "reader@domain.com");
 *
 * Maka IsRoleValid akan mengembalikan nilai TRUE jika :
 *
 *  1. $supplied = array("user@domain.com", "reader@domain.com"); // pengakses memiliki role yang diperlukan.
 *  2. $supplied = array("*@domain.com") // pengakses memiliki role yang secara pola/pattern memenuhi semua syarat role dalam $required.
 *  3. $supplied = array("*@domain.com", "abc@other.com"); // pengakses memiliki role yang salah satunya, secara pola/pattern, memenuhi semua syarat role dalam $required.
 *
 * Contoh 2 :
 *      $required = array("*@domain.com");
 *
 * Maka IsRoleValid akan mengembalikan nilai TRUE jika :
 *
 *  1. $supplied = array("user@domain.com"); // pengakses memiliki role yang memenuhi pola syarat role dalam $required.
 *  2. $supplied = array("user@domain.com", "abc@other.com"); // pengakses memiliki role yang salah satunya memenuhi pola syarat role dalam $required.
 *
 * CATATAN : $required yang memiliki role dengan pola wildcard, tidak bisa dipenuhi dengan $supplied yang juga menggunakan pola wildcard.
 *           Contoh :
 *
 * NeverAllowed = IsRoleValid(array("*@domain.com"), array("writer@*"));
 *
 * Silahkan lihat contoh testing di bagian bawah sourcecode ini.
 */
function IsRoleValid($requires, $supplied) {
  if (count( (array) $requires) == 0) {
      return TRUE;
  }
  $valid = FALSE;
  for ($i = 0; $i < count( (array) $requires); $i++) {
    $requireValid = FALSE;
    for ($j = 0; $j < count( (array) $supplied); $j++) {
        if (MatchesTwoRole($requires[$i], $supplied[$j]) == TRUE) {
            $valid = TRUE;
            $requireValid = TRUE;
        }
    }
    if ($requireValid == FALSE) {
        return FALSE;
    }
  }
  return $valid;
}

/**
 * MatchesTwoRole ini adalah fungsi sederhana yang dipergunakan oleh fungsi IsRoleValid
 * untuk membandingkan apakah diantara 2 string bisa saling memenuhi pola role diantara mereka.
 *
 * Contoh :
 *  Jika $a = "abcd@efghijk.lmn.com";
 *
 * Maka fungsi MatchesTwoRole akan mengembalikan nilai TRUE jika:
 *  1. $b = "abcd@efghijk.lmn.com"; // dimana $b sama persis dengan $a.
 *  2. $b = "*@efghijk.lmn.com"; // dimana $b memiliki pola yang cocok dengan $a.
 *  3. $b = "*@*"; // $b memiliki pola yang cocok dengan $a (variasi pola)
 *  4. $b = "*cd@efghijk.*"; // $b memiliki pola yang cocok dengan $a (variasi pola)
 */
function MatchesTwoRole($a, $b) {
    $aw = strpos($a, '*');
    $bw = strpos($b, '*');
    if ($aw !== FALSE && $bw !== FALSE) {
        return FALSE;
    }
    if ($aw === FALSE && $bw === FALSE) {
		return $a == $b;
	}
    if ($aw !== FALSE) {
        $pattern = '/^'.str_replace('*', '[a-zA-Z0-9_\-\.]+', str_replace("-","\\-",$a)).'$/';
        return preg_match($pattern, $b);
    }
    if ($bw !== FALSE) {
        $pattern = '/^'.str_replace('*', '[a-zA-Z0-9_\-\.]+', str_replace("-","\\-",$b)).'$/';
        return preg_match($pattern, $a);
    }
    return FALSE;
}

// ---------------- unit testing ------------------

function Test($no, $expect, $required, $supplied) {
    if ($expect != IsRoleValid($required, $supplied)) {
        print("Test " . $no . " failed.\n");
    } else {
        print("Test " . $no . " success.\n");
    }
}

Test(1, TRUE, array("basic@app.idntimes.com"), array("basic@app.idntimes.com"));
Test(2, FALSE, array("basic@app.idntimes.com"), array("anon@app.idntimes.com"));
Test(3, FALSE, array("basic@app.idntimes.com"), array("anon@app.idntimes.com", "admin@app.idntimes.com"));
Test(4, FALSE, array("reg-sum-edt@app.idntimes.com"), array("reg-sul-edt@app.idntimes.com", "reg-abc-edt@app.idntimes.com"));
Test(5, TRUE, array("reg-sum-edt@app.idntimes.com"), array("reg-sul-edt@app.idntimes.com", "reg-*-edt@app.idntimes.com"));
Test(6, TRUE, array("reg-*-edt@app.idntimes.com"), array("reg-sul-edt@app.idntimes.com", "reg-*-edt@app.idntimes.com"));
Test(7, TRUE, array("reg-*-edt@app.idntimes.com"), array("reg-sul-edt@app.idntimes.com", "reg--edt@app.idntimes.com"));
Test(8, FALSE, array("reg-*-edt@app.idntimes.com"), array("reg-sul-wow@app.idntimes.com", "reg--edt@app.idntimes.com"));
Test(9, FALSE, array("basic@app.idntimes.com"), array());
Test(10, TRUE, array(), array("basic@app.idntimes.com"));
Test(11, TRUE, array("basic@app.idntimes.com"), array("basic@app.idntimes.com"));
Test(12, TRUE, array("*@app.idntimes.com"), array("basic@app.idntimes.com"));
Test(13, TRUE, array("basic@app.idntimes.com"), array("*@app.idntimes.com"));
Test(14, TRUE, array("basic@app.idntimes.com", "admin@app.idntimes.com"), array("*@app.idntimes.com"));
Test(15, TRUE, array("*@app.idntimes.com"), array("basic@app.idntimes.com", "admin@app.idntimes.com"));
Test(16, FALSE, array("*@app.idntimes.com"), array("basic@popmama.com", "admin@popmama.com"));
Test(17, TRUE, array("basic@app.idntimes.com"), array("basic@popmama.com", "*@app.idntimes.com"));
Test(18, TRUE, array("basic@app-fuse.idntimes.com"), array("basic@popmama.com", "basic@*.idntimes.com"));
Test(19, TRUE, array("basic@app.idntimes.com"), array("basic@popmama.com", "basic@*.idntimes.com"));
Test(20, TRUE, array("basic@app.idntimes.com"), array("basic@popmama.com", "basic@*.com"));
Test(21, TRUE, array("basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"), array("*@*"));
Test(22, TRUE, array("*@*"), array("basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"));
Test(23, FALSE, array("*"), array("basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"));
Test(24, FALSE, array("basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"), array("*"));
Test(25, FALSE, array("basic@app.idntimes.com", "admin@app.idntimes.com"), array("basic@app.idntimes.com", "abc@app.idntimes.com", "cde@app.idntimes.com", "efg@app.idntimes.com"));

?>