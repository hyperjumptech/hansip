package helper

import "testing"

type RoleCheckTest struct {
	Success  bool
	Required []string
	Supplied []string
}

func TestIsRoleValid(t *testing.T) {
	TestData := []RoleCheckTest{
		{
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"basic@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"anon@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"anon@app.idntimes.com", "admin@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"reg-sum-edt@app.idntimes.com"},
			Supplied: []string{"reg-sul-edt@app.idntimes.com", "reg-abc-edt@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"reg-sum-edt@app.idntimes.com"},
			Supplied: []string{"reg-sul-edt@app.idntimes.com", "reg-*-edt@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"reg-*-edt@app.idntimes.com"},
			Supplied: []string{"reg-sul-edt@app.idntimes.com", "reg-*-edt@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"reg-*-edt@app.idntimes.com"},
			Supplied: []string{"reg-sul-edt@app.idntimes.com", "reg--edt@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"reg-*-edt@app.idntimes.com"},
			Supplied: []string{"reg-sul-wow@app.idntimes.com", "reg--edt@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{},
		}, {
			Success:  true,
			Required: []string{},
			Supplied: []string{"basic@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"basic@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"*@app.idntimes.com"},
			Supplied: []string{"basic@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"*@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com", "admin@app.idntimes.com"},
			Supplied: []string{"*@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"*@app.idntimes.com"},
			Supplied: []string{"basic@app.idntimes.com", "admin@app.idntimes.com"},
		}, {
			Success:  false,
			Required: []string{"*@app.idntimes.com"},
			Supplied: []string{"basic@popmama.com", "admin@popmama.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"basic@popmama.com", "*@app.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app-fuse.idntimes.com"},
			Supplied: []string{"basic@popmama.com", "basic@*.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"basic@popmama.com", "basic@*.idntimes.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com"},
			Supplied: []string{"basic@popmama.com", "basic@*.com"},
		}, {
			Success:  true,
			Required: []string{"basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"},
			Supplied: []string{"*@*"},
		}, {
			Success:  true,
			Required: []string{"*@*"},
			Supplied: []string{"basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"},
		}, {
			Success:  false,
			Required: []string{"*"},
			Supplied: []string{"basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"},
		}, {
			Success:  false,
			Required: []string{"basic@app.idntimes.com", "admin@app.idntimes.com", "abc@popmama.com"},
			Supplied: []string{"*"},
		}, {
			Success:  false,
			Required: []string{"basic@app.idntimes.com", "admin@app.idntimes.com"},
			Supplied: []string{"basic@app.idntimes.com", "abc@app.idntimes.com", "cde@app.idntimes.com", "efg@app.idntimes.com"},
		},
	}

	for i, td := range TestData {
		if td.Success != IsRoleValid(td.Required, td.Supplied) {
			t.Logf("Test %d expect is %v but %v", i, td.Success, IsRoleValid(td.Required, td.Supplied))
			t.Fail()
		}
	}
}
