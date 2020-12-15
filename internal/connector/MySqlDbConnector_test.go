package connector

import (
	"context"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"testing"
)

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
