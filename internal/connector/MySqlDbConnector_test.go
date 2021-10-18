package connector

import (
	"context"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"sort"
	"testing"
)

func TestSorting(t *testing.T) {
	arr := []string{
		"abc", "cde",
	}
	sort.Slice(arr, func(i, j int) bool {
		return i < j
	})
	if arr[0] != "abc" {
		t.Log(arr[0])
		t.FailNow()
	}
}

func TestUpdateuser(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	db, err := sql.Open("mysql", "devuser:devpassword@/devdb?parseTime=true")
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}

	if db == nil {
		t.Log("DB nill")
		t.FailNow()
	}

	mysqldb := &MySQLDB{instance: db}

	ctx := context.Background()

	user, err := mysqldb.GetUserByEmail(ctx, "ferdinand.neman@gmail.com")
	if err != nil {
		t.FailNow()
	}

	//user.Enabled = true
	user.FailCount = 1

	err = mysqldb.UpdateUser(ctx, user)
	if err != nil {
		t.Fail()
	}
}
