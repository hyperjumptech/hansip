package endpoint

import "testing"

type TestAccess struct {
	Path          string
	Method        uint8
	Roles         []string
	ExpectNoError bool
}

func TestEndpoint_CanAccess(t *testing.T) {
	e := Endpoint{
		PathPattern:        "/v1/test/{someparam}/{otherparam}",
		IsPublic:           false,
		AllowedMethodFlag:  OptionMethod | GetMethod,
		WhiteListAudiences: []string{"admin@*", "user@*"},
		HandleFunction:     nil,
	}

	testData := []*TestAccess{
		// test roles
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{"admin@tokopedia"}, true},
		&TestAccess{"/v1/test/def/abc", OptionMethod, []string{"admin@tokopedia"}, true},
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{}, false},
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{"user@tokopedia"}, true},
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{"anonymous@tokopedia"}, false},
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{"anonymous@tokopedia", "admin@tokopedia"}, true},
		&TestAccess{"/v1/test/abc/def", OptionMethod, []string{"anonymous@tokopedia", "unknown@tokopedia"}, false},
		// test paths
		&TestAccess{"/v1/test/what/abc/def", OptionMethod, []string{"admin@tokopedia"}, false},
		&TestAccess{"/v1/what/abc/def", OptionMethod, []string{"admin@tokopedia"}, false},
		// test method
		&TestAccess{"/v1/test/abc/def", PutMethod, []string{"admin@tokopedia"}, false},
	}

	for i, tst := range testData {
		if tst.ExpectNoError && e.canAccess(tst.Path, tst.Method, tst.Roles) != nil {
			t.Logf("#%d fail", i)
			t.Fail()
		}
	}
}
