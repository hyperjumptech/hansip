package helper

// StringArrayContainString returns true if the array contains specified string.
func StringArrayContainString(array []string, s string) bool {
	for _, v := range array {
		if v == s {
			return true
		}
	}
	return false
}
