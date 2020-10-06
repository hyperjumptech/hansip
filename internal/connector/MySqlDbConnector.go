package connector

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"

	// Initializes mysql driver
	_ "github.com/go-sql-driver/mysql"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"sort"
	"time"
)

const (
	// DropAllSQL contains SQL to drop all existing table for hansip
	DropAllSQL = `DROP TABLE IF EXISTS HANSIP_USER_GROUP, HANSIP_USER_ROLE, HANSIP_GROUP_ROLE, HANSIP_USER, HANSIP_GROUP, HANSIP_ROLE;`
	// CreateUserSQL will create HANSIP_USER table
	CreateUserSQL = `CREATE TABLE IF NOT EXISTS HANSIP_USER (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    EMAIL VARCHAR(128)  NOT NULL UNIQUE,
    HASHED_PASSPHRASE VARCHAR(128),
    ENABLED TINYINT(1) UNSIGNED DEFAULT 0,
    SUSPENDED TINYINT(1) UNSIGNED DEFAULT 0,
    LAST_SEEN DATETIME,
    LAST_LOGIN DATETIME,
    FAIL_COUNT INT DEFAULT 0,
    ACTIVATION_CODE VARCHAR(32),
    ACTIVATION_DATE DATETIME,
    TOTP_KEY VARCHAR(64),
    ENABLE_2FE TINYINT(1) UNSIGNED DEFAULT 0,
    TOKEN_2FE VARCHAR(10),
    RECOVERY_CODE VARCHAR (20),
    INDEX (REC_ID, EMAIL),
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	// CreateGroupSQL contains SQL to  create HANSIP_GROUP
	CreateGroupSQL = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    GROUP_NAME VARCHAR(128) NOT NULL UNIQUE,
    DESCRIPTION VARCHAR(255),
    INDEX (REC_ID, GROUP_NAME),
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	// CreateRoleSQL contains SQL to create HANSIP_ROLE table
	CreateRoleSQL = `CREATE TABLE IF NOT EXISTS HANSIP_ROLE (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    ROLE_NAME VARCHAR(128) NOT NULL UNIQUE,
    DESCRIPTION VARCHAR(255),
    INDEX (REC_ID, ROLE_NAME),
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	// CreateUserRoleSQL contains SQL to create HANSIP_USER_ROLE table
	CreateUserRoleSQL = `CREATE TABLE IF NOT EXISTS HANSIP_USER_ROLE (
    USER_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
	// CreateUserGroupSQL contains SQL to create HANSIP_USER_GROUP
	CreateUserGroupSQL = `CREATE TABLE IF NOT EXISTS HANSIP_USER_GROUP (
    USER_REC_ID VARCHAR(32) NOT NULL,
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,GROUP_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
	// CreateGroupRoleSQL contains SQL to create HANSIP_GROUP_ROLE table
	CreateGroupRoleSQL = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP_ROLE (
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (GROUP_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
	// CreateTOTPRecoveryCodeSQL contains SQL to create HANSIP_TOTP_RECOVERY_CODES table
	CreateTOTPRecoveryCodeSQL = `CREATE TABLE IF NOT EXISTS HANSIP_TOTP_RECOVERY_CODES (
    REC_ID VARCHAR(32) NOT NULL,
    RECOVERY_CODE VARCHAR(8) NOT NULL,
    USED_FLAG TINYINT(1) UNSIGNED DEFAULT 0,
    USER_REC_ID VARCHAR(32) NOT NULL,
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
)

var (
	mysqlLog        = log.WithField("go", "MySqlDbConnector")
	mySQLDBInstance *MySQLDB
)

// GetMySQLDBInstance will obtain the singleton instance to MySQLDB
func GetMySQLDBInstance() *MySQLDB {
	if mySQLDBInstance == nil {
		host := config.Get("db.mysql.host")
		port := config.GetInt("db.mysql.port")
		user := config.Get("db.mysql.user")
		password := config.Get("db.mysql.password")
		database := config.Get("db.mysql.database")
		db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", user, password, host, port, database))
		if err != nil {
			mysqlLog.WithField("func", "GetMySQLDBInstance").Fatalf("sql.Open got %s", err.Error())
		}
		db.SetMaxOpenConns(config.GetInt("db.mysql.maxopen"))
		db.SetMaxIdleConns(config.GetInt("db.mysql.maxidle"))
		mySQLDBInstance = &MySQLDB{
			instance: db,
		}
		err = mySQLDBInstance.InitDB(context.Background())
		if err != nil {
			mysqlLog.WithField("func", "GetMySQLDBInstance").Fatalf("mySQLDBInstance.InitDB got %s", err.Error())
		}
	}
	return mySQLDBInstance
}

// MySQLDB is a struct to hold sql.DB pointer
type MySQLDB struct {
	instance *sql.DB
}

// InitDB will initialize this connector.
func (db *MySQLDB) InitDB(ctx context.Context) error {
	fLog := mysqlLog.WithField("func", "InitDB")

	fLog.Infof("Checking table HANSIP_USER")
	exist, err := db.isTableExist(ctx, "HANSIP_USER")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER")
		_, err := db.instance.ExecContext(ctx, CreateUserSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER Got %s", err.Error())
		}
	}

	fLog.Infof("Checking table HANSIP_GROUP")
	exist, err = db.isTableExist(ctx, "HANSIP_GROUP")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_GROUP")
		_, err := db.instance.ExecContext(ctx, CreateGroupSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_GROUP Got %s", err.Error())
		}
	}

	fLog.Infof("Checking table HANSIP_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateRoleSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_ROLE Got %s", err.Error())
		} else {
			fLog.Infof("Create Roles")
			_, err = db.CreateRole(ctx, "admin@aaa", "Administrator role")
			if err != nil {
				fLog.Errorf("db.CreateRole Got %s", err.Error())
			}
			_, err = db.CreateRole(ctx, "user@aaa", "Administrator role")
			if err != nil {
				fLog.Errorf("db.CreateRole Got %s", err.Error())
			}
		}
	}

	fLog.Infof("Checking table HANSIP_USER_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_USER_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateUserRoleSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER_ROLE Got %s", err.Error())
		}
	}

	fLog.Infof("Checking table HANSIP_USER_GROUP")
	exist, err = db.isTableExist(ctx, "HANSIP_USER_GROUP")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_USER_GROUP")
		_, err := db.instance.ExecContext(ctx, CreateUserGroupSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_USER_GROUP Got %s", err.Error())
		}
	}

	fLog.Infof("Checking table HANSIP_GROUP_ROLE")
	exist, err = db.isTableExist(ctx, "HANSIP_GROUP_ROLE")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_GROUP_ROLE")
		_, err := db.instance.ExecContext(ctx, CreateGroupRoleSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s", err.Error())
		}
	}

	fLog.Infof("Checking table HANSIP_TOTP_RECOVERY_CODES")
	exist, err = db.isTableExist(ctx, "HANSIP_TOTP_RECOVERY_CODES")
	if err != nil {
		return err
	}
	if !exist {
		fLog.Infof("Create table HANSIP_TOTP_RECOVERY_CODES")
		_, err := db.instance.ExecContext(ctx, CreateTOTPRecoveryCodeSQL)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext HANSIP_TOTP_RECOVERY_CODES Got %s", err.Error())
		}
	}

	return nil
}

func (db *MySQLDB) isTableExist(ctx context.Context, tableName string) (bool, error) {
	fLog := mysqlLog.WithField("func", "isTableExist")
	rows, err := db.instance.QueryContext(ctx, "select COUNT(*) AS CNT from INFORMATION_SCHEMA.TABLES where TABLE_NAME=?", tableName)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsUserRecIDExist cant scan")
	return false, fmt.Errorf("db.instance.IsUserRecIDExist cant scan")
}

// DropAllTables will drop all tables used by Hansip
func (db *MySQLDB) DropAllTables(ctx context.Context) error {
	_, err := db.instance.ExecContext(ctx, DropAllSQL)
	if err != nil {
		mysqlLog.WithField("func", "DropAllTables").WithField("RequestID", ctx.Value(constants.RequestID)).Errorf("got %s", err.Error())
	}
	return err
}

// CreateAllTable creates all table used by Hansip
func (db *MySQLDB) CreateAllTable(ctx context.Context) error {
	fLog := mysqlLog.WithField("func", "CreateAllTable").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, CreateUserSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateGroupSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateRoleSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_ROLE Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateUserRoleSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_ROLE Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateUserGroupSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_GROUP Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateGroupRoleSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CreateTOTPRecoveryCodeSQL)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_TOTP_RECOVERY_CODES Got %s", err.Error())
	}
	_, err = db.CreateRole(ctx, "admin@aaa", "Administrator role")
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s", err.Error())
	}
	_, err = db.CreateRole(ctx, "user@aaa", "Administrator role")
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s", err.Error())
	}
	return err
}

// GetUserByRecID get user data by its RecID
func (db *MySQLDB) GetUserByRecID(ctx context.Context, recID string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE REC_ID = ?", recID)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
		&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, err
	}
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// CreateUserRecord create a new user
func (db *MySQLDB) CreateUserRecord(ctx context.Context, email, passphrase string) (*User, error) {
	fLog := mysqlLog.WithField("func", "CreateUserRecord").WithField("RequestID", ctx.Value(constants.RequestID))
	bytes, err := bcrypt.GenerateFromPassword([]byte(passphrase), 14)
	if err != nil {
		fLog.Errorf("bcrypt.GenerateFromPassword got %s", err.Error())
		return nil, err
	}
	user := &User{
		RecID:             helper.MakeRandomString(10, true, true, true, false),
		Email:             email,
		HashedPassphrase:  string(bytes),
		Enabled:           false,
		Suspended:         false,
		LastSeen:          time.Now(),
		LastLogin:         time.Now(),
		FailCount:         0,
		ActivationCode:    helper.MakeRandomString(6, true, false, false, false),
		ActivationDate:    time.Now(),
		Enable2FactorAuth: false,
		UserTotpSecretKey: totp.MakeSecret().Base32(),
		Token2FA:          helper.MakeRandomString(6, true, false, false, false),
		RecoveryCode:      helper.MakeRandomString(6, true, false, false, false),
	}

	_, err = db.instance.ExecContext(ctx, "INSERT INTO HANSIP_USER(REC_ID,EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		user.RecID, user.Email, user.HashedPassphrase, 0, 0, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
		user.ActivationDate, user.UserTotpSecretKey, user.Enable2FactorAuth, user.Token2FA, user.RecoveryCode)

	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		return nil, err
	}

	return user, nil
}

// GetTOTPRecoveryCodes retrieves all valid/not used TOTP recovery codes.
func (db *MySQLDB) GetTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {
	fLog := mysqlLog.WithField("func", "GetTOTPRecoveryCodes").WithField("RequestID", ctx.Value(constants.RequestID))

	ret := make([]string, 0)
	rows, err := db.instance.QueryContext(ctx, "SELECT RECOVERY_CODE FROM HANSIP_TOTP_RECOVERY_CODES WHERE USER_REC_ID = ? && USED_FLAG = ?", user.RecID, 0)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s", err.Error())
		return nil, err
	}
	for rows.Next() {
		code := ""
		err = rows.Scan(&code)
		if err != nil {
			fLog.Errorf("rows.Scan got %s", err.Error())
		} else {
			ret = append(ret, code)
		}
	}
	return ret, nil
}

// RecreateTOTPRecoveryCodes recreates 16 new recovery codes.
func (db *MySQLDB) RecreateTOTPRecoveryCodes(ctx context.Context, user *User) ([]string, error) {
	fLog := mysqlLog.WithField("func", "RecreateTOTPRecoveryCodes").WithField("RequestID", ctx.Value(constants.RequestID))

	// first we clear out all existing codes.
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_TOTP_RECOVERY_CODES WHERE USER_REC_ID = ?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		return nil, err
	}

	// Now lets recreate all new records.
	ret := make([]string, 0)
	for i := 0; i < 16; i++ {
		recID := helper.MakeRandomString(10, true, true, true, false)
		code := helper.MakeRandomString(8, true, false, true, false)
		_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_TOTP_RECOVERY_CODES(REC_ID, RECOVERY_CODE, USED_FLAG, USER_REC_ID) VALUES (?,?,?,?)", recID, code, 0, user.RecID)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		} else {
			ret = append(ret, code)
		}
	}
	return ret, nil
}

// MarkTOTPRecoveryCodeUsed will mark the specific recovery code as used and thus can not be used anymore.
func (db *MySQLDB) MarkTOTPRecoveryCodeUsed(ctx context.Context, user *User, code string) error {
	fLog := mysqlLog.WithField("func", "MarkTOTPRecoveryCodeUsed").WithField("RequestID", ctx.Value(constants.RequestID))

	rexp := regexp.MustCompile(`^[A-Z0-9]{8}$`)
	if rexp.Match([]byte(code)) {
		_, err := db.instance.ExecContext(ctx, "UPDATE HANSIP_TOTP_RECOVERY_CODES SET USED_FLAG = ? WHERE USER_REC_ID = ? AND RECOVERY_CODE=?", 1, user.RecID, code)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		}
		return err
	}
	fLog.Warnf("Invalid Code format. expect 8 digit contains capital Alphabet and number only. But %s", code)
	return nil
}

// GetUserByEmail get user record by its email address
func (db *MySQLDB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserByEmail").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE EMAIL = ?", email)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
		&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, err
	}
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// GetUserBy2FAToken get a user by its 2FA token
func (db *MySQLDB) GetUserBy2FAToken(ctx context.Context, token string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserBy2FAToken").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE TOKEN_2FE = ?", token)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
		&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, err
	}
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// GetUserByRecoveryToken get a user by its recovery token
func (db *MySQLDB) GetUserByRecoveryToken(ctx context.Context, token string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserByRecoveryToken").WithField("RequestID", ctx.Value(constants.RequestID))
	user := &User{}
	var enabled, suspended, enable2fa int
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER WHERE RECOVERY_CODE = ?", token)
	err := row.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
		&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
	if err != nil {
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, err
	}
	if enabled == 1 {
		user.Enabled = true
	}
	if suspended == 1 {
		user.Suspended = true
	}
	if enable2fa == 1 {
		user.Enable2FactorAuth = true
	}
	return user, nil
}

// DeleteUser delete a user
func (db *MySQLDB) DeleteUser(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "DeleteUser").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER WHERE REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// IsUserRecIDExist check if a specific user recId is exist in database
func (db *MySQLDB) IsUserRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsUserRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_USER WHERE REC_ID=?", recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsUserRecIDExist cant scan")
	return false, fmt.Errorf("db.instance.IsUserRecIDExist cant scan")
}

// SaveOrUpdate save or update a user data
func (db *MySQLDB) SaveOrUpdate(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdate").WithField("RequestID", ctx.Value(constants.RequestID))
	updating, err := db.IsUserRecIDExist(ctx, user.RecID)
	if err != nil {
		fLog.Errorf("db.IsUserRecIDExist got %s", err.Error())
		return err
	}
	enabled := 0
	suspended := 0
	enable2fa := 0
	if user.Enabled {
		enabled = 1
	}
	if user.Suspended {
		suspended = 1
	}
	if user.Enable2FactorAuth {
		enable2fa = 1
	}
	if !updating {
		fLog.Infof("Creating user %s", user.Email)
		_, err = db.instance.ExecContext(ctx, "INSERT INTO HANSIP_USER(REC_ID,EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			user.RecID, user.Email, user.HashedPassphrase, enabled, suspended, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
			user.ActivationDate, user.UserTotpSecretKey, enable2fa, user.Token2FA, user.RecoveryCode)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		}
		return err
	}
	fLog.Infof("Updating user %s", user.Email)
	_, err = db.instance.ExecContext(ctx, "UPDATE HANSIP_USER SET EMAIL=?,HASHED_PASSPHRASE=?,ENABLED=?, SUSPENDED=?,LAST_SEEN=?,LAST_LOGIN=?,FAIL_COUNT=?,ACTIVATION_CODE=?,ACTIVATION_DATE=?,TOTP_KEY=?,ENABLE_2FE=?,TOKEN_2FE=?,RECOVERY_CODE=? WHERE REC_ID=?",
		user.Email, user.HashedPassphrase, enabled, suspended, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
		user.ActivationDate, user.UserTotpSecretKey, enable2fa, user.Token2FA, user.RecoveryCode, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// ListUser list all user paginated
func (db *MySQLDB) ListUser(ctx context.Context, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUser").WithField("RequestID", ctx.Value(constants.RequestID))
	count, err := db.Count(ctx)
	if err != nil {
		fLog.Errorf("db.Count got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	userList := make([]*User, 0)
	q := fmt.Sprintf("SELECT REC_ID, EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE FROM HANSIP_USER ORDER BY %s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	rows, err := db.instance.QueryContext(ctx, q)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
			&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got %s", err.Error())
		} else {
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			userList = append(userList, user)
		}
	}
	return userList, page, nil
}

// Count all user
func (db *MySQLDB) Count(ctx context.Context) (int, error) {
	fLog := mysqlLog.WithField("func", "Count").WithField("RequestID", ctx.Value(constants.RequestID))
	count := 0
	err := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) as CNT FROM HANSIP_USER").Scan(&count)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got %s", err.Error())
		return 0, err
	}
	return count, nil
}

// ListAllUserRoles list all user's roles direct and indirect
func (db *MySQLDB) ListAllUserRoles(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListAllUserRoles").WithField("RequestID", ctx.Value(constants.RequestID))
	roleMap := make(map[string]*Role)
	rows, err := db.instance.QueryContext(ctx, "SELECT R.REC_ID, R.ROLE_NAME, R.DESCRIPTION FROM HANSIP_ROLE R, HANSIP_USER_ROLE UR WHERE R.REC_ID = UR.ROLE_REC_ID AND UR.USER_REC_ID = ?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		r := &Role{}
		err = rows.Scan(&r.RecID, &r.RoleName, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			roleMap[r.RecID] = r
		}
	}
	rows, err = db.instance.QueryContext(ctx, "SELECT DISTINCT R.REC_ID, R.ROLE_NAME, R.DESCRIPTION FROM HANSIP_ROLE R, HANSIP_GROUP_ROLE GR, HANSIP_USER_GROUP UG WHERE R.REC_ID = GR.ROLE_REC_ID AND GR.GROUP_REC_ID = UG.GROUP_REC_ID AND UG.USER_REC_ID = ?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		r := &Role{}
		err = rows.Scan(&r.RecID, &r.RoleName, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			roleMap[r.RecID] = r
		}
	}

	page := helper.NewPage(request, uint(len(roleMap)))
	roles := make([]*Role, 0)
	for _, v := range roleMap {
		roles = append(roles, v)
	}
	if request.OrderBy == "ROLE_NAME" {
		if request.Sort == "ASC" {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName < roles[j].RoleName
			})
		} else {
			sort.SliceStable(roles, func(i, j int) bool {
				return roles[i].RoleName > roles[j].RoleName
			})
		}
	}
	return roles[page.OffsetStart:page.OffsetEnd], page, nil
}

// GetUserRole return user's assigned roles
func (db *MySQLDB) GetUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	fLog := mysqlLog.WithField("func", "GetUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) CNT FROM HANSIP_USER_ROLE WHERE USER_REC_ID=? AND ROLE_REC_ID=?", user.RecID, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
		return nil, err
	}
	return &UserRole{
		UserRecID: user.RecID,
		RoleRecID: role.RecID,
	}, nil
}

// CreateUserRole assign a role to a user.
func (db *MySQLDB) CreateUserRole(ctx context.Context, user *User, role *Role) (*UserRole, error) {
	fLog := mysqlLog.WithField("func", "CreateUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_USER_ROLE(USER_REC_ID, ROLE_REC_ID) VALUES (?,?)", user.RecID, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		return nil, err
	}
	return &UserRole{
		UserRecID: user.RecID,
		RoleRecID: role.RecID,
	}, nil
}

// ListUserRoleByUser get all roles assigned to a user, paginated
func (db *MySQLDB) ListUserRoleByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserRoleByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_USER_ROLE WHERE USER_REC_ID=?", user.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID, R.ROLE_NAME, R.DESCRIPTION FROM HANSIP_USER_ROLE UR, HANSIP_ROLE R WHERE UR.ROLE_REC_ID = R.REC_ID AND UR.USER_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Role, 0)
	rows, err := db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		r := &Role{}
		err := rows.Scan(&r.RecID, &r.RoleName, &r.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// ListUserRoleByRole list all user that related to a role
func (db *MySQLDB) ListUserRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_USER_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID,R.EMAIL,R.HASHED_PASSPHRASE,R.ENABLED, R.SUSPENDED,R.LAST_SEEN,R.LAST_LOGIN,R.FAIL_COUNT,R.ACTIVATION_CODE,R.ACTIVATION_DATE,R.TOTP_KEY,R.ENABLE_2FE,R.TOKEN_2FE,R.RECOVERY_CODE FROM HANSIP_USER_ROLE UR, HANSIP_USER R WHERE UR.USER_REC_ID = R.REC_ID AND UR.ROLE_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*User, 0)
	rows, err := db.instance.QueryContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
			&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			ret = append(ret, user)
		}
	}
	return ret, page, nil
}

// DeleteUserRole remove a role from user's assigment
func (db *MySQLDB) DeleteUserRole(ctx context.Context, userRole *UserRole) error {
	fLog := mysqlLog.WithField("func", "DeleteUserRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=? AND ROLE_REC_ID=?", userRole.UserRecID, userRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteUserRoleByUser remove ALL role assigment of a user
func (db *MySQLDB) DeleteUserRoleByUser(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "DeleteUserRoleByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteUserRoleByRole remove all user-role assigment to a role
func (db *MySQLDB) DeleteUserRoleByRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "DeleteUserRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetRoleByRecID return a role with speciffic recID
func (db *MySQLDB) GetRoleByRecID(ctx context.Context, recID string) (*Role, error) {
	fLog := mysqlLog.WithField("func", "GetRoleByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, ROLE_NAME, DESCRIPTION FROM HANSIP_ROLE WHERE REC_ID=?", recID)
	r := &Role{}
	err := row.Scan(&r.RecID, &r.RoleName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
	}
	return r, err
}

// GetRoleByName return a role record
func (db *MySQLDB) GetRoleByName(ctx context.Context, roleName string) (*Role, error) {
	fLog := mysqlLog.WithField("func", "GetRoleByName").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, ROLE_NAME, DESCRIPTION FROM HANSIP_ROLE WHERE ROLE_NAME=?", roleName)
	r := &Role{}
	err := row.Scan(&r.RecID, &r.RoleName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
	}
	return nil, fmt.Errorf("not found")
}

// CreateRole creates a new role
func (db *MySQLDB) CreateRole(ctx context.Context, roleName, description string) (*Role, error) {
	fLog := mysqlLog.WithField("func", "CreateRole").WithField("RequestID", ctx.Value(constants.RequestID))
	r := &Role{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		RoleName:    roleName,
		Description: description,
	}
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_ROLE(REC_ID, ROLE_NAME, DESCRIPTION) VALUES (?,?,?)", r.RecID, roleName, description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return r, err
}

// ListRoles list all roles in this server
func (db *MySQLDB) ListRoles(ctx context.Context, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListRoles").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_ROLE")
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT REC_ID, ROLE_NAME, DESCRIPTION FROM HANSIP_ROLE ORDER BY %s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Role, 0)
	rows, err := db.instance.QueryContext(ctx, q)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		r := &Role{}
		err := rows.Scan(&r.RecID, &r.RoleName, &r.Description)
		if err != nil {
			fLog.Warnf("row.Scan got  %s", err.Error())
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// DeleteRole delete a specific role from this server
func (db *MySQLDB) DeleteRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "DeleteRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_ROLE WHERE REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// IsRoleRecIDExist check if a speciffic role recId is exist in database
func (db *MySQLDB) IsRoleRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsUserRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_ROLE WHERE REC_ID=?", recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsRoleRecIDExist cant scan")
	return false, fmt.Errorf("db.instance.IsRoleRecIDExist cant scan")
}

// SaveOrUpdateRole save or update a role record
func (db *MySQLDB) SaveOrUpdateRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdateRole").WithField("RequestID", ctx.Value(constants.RequestID))
	updating := false
	if len(role.RecID) == 0 {
		role.RecID = helper.MakeRandomString(10, true, true, true, false)
		updating = false
	} else {
		update, err := db.IsRoleRecIDExist(ctx, role.RecID)
		if err != nil {
			return err
		}
		updating = update
	}
	if updating {
		_, err := db.instance.ExecContext(ctx, "UPDATE HANSIP_ROLE SET ROLE_NAME=?, DESCRIPTION=? WHERE REC_ID=?",
			role.RoleName, role.Description, role.RecID)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
		}
		return err
	}
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_ROLE(REC_ID,ROLE_NAME,DESCRIPTION) VALUES(?,?,?)",
		role.RecID, role.RoleName, role.Description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetGroupByRecID return a Group data by its RedID
func (db *MySQLDB) GetGroupByRecID(ctx context.Context, recID string) (*Group, error) {
	fLog := mysqlLog.WithField("func", "GetGroupByRecID").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, GROUP_NAME, DESCRIPTION FROM HANSIP_GROUP WHERE REC_ID=?", recID)
	r := &Group{}
	err := row.Scan(&r.RecID, &r.GroupName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got %s", err.Error())
	}
	return r, err
}

func (db *MySQLDB) GetGroupByName(ctx context.Context, groupName string) (*Group, error) {
	fLog := mysqlLog.WithField("func", "GetGroupByName").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, GROUP_NAME, DESCRIPTION FROM HANSIP_GROUP WHERE GROUP_NAME=?", groupName)
	r := &Group{}
	err := row.Scan(&r.RecID, &r.GroupName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got %s", err.Error())
	}
	return r, err
}

// CreateGroup create new Group
func (db *MySQLDB) CreateGroup(ctx context.Context, groupName, description string) (*Group, error) {
	fLog := mysqlLog.WithField("func", "CreateGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	r := &Group{
		RecID:       helper.MakeRandomString(10, true, true, true, false),
		GroupName:   groupName,
		Description: description,
	}
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_GROUP(REC_ID, GROUP_NAME, DESCRIPTION) VALUES (?,?,?)", r.RecID, groupName, description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return r, err
}

// ListGroups list all groups in this server
func (db *MySQLDB) ListGroups(ctx context.Context, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListGroups").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_GROUP")
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT REC_ID, GROUP_NAME, DESCRIPTION FROM HANSIP_GROUP ORDER BY %s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Group, 0)
	rows, err := db.instance.QueryContext(ctx, q)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		r := &Group{}
		err := rows.Scan(&r.RecID, &r.GroupName, &r.Description)
		if err != nil {
			fLog.Warnf("row.Scan got  %s", err.Error())
		} else {
			ret = append(ret, r)
		}
	}
	return ret, page, nil
}

// DeleteGroup delete one speciffic group
func (db *MySQLDB) DeleteGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "DeleteGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP WHERE REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// IsGroupRecIDExist check if a speciffic group recId is exist in database
func (db *MySQLDB) IsGroupRecIDExist(ctx context.Context, recID string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsGroupRecIDExist").WithField("RequestID", ctx.Value(constants.RequestID))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_GROUP WHERE REC_ID=?", recID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsGroupRecIDExist cant scan")
	return false, fmt.Errorf("db.instance.IsGroupRecIDExist cant scan")
}

// SaveOrUpdateGroup delete one specific group
func (db *MySQLDB) SaveOrUpdateGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdateGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	updating := false
	if len(group.RecID) == 0 {
		group.RecID = helper.MakeRandomString(10, true, true, true, false)
		updating = false
	} else {
		update, err := db.IsGroupRecIDExist(ctx, group.RecID)
		if err != nil {
			return err
		}
		updating = update
	}
	if updating {
		_, err := db.instance.ExecContext(ctx, "UPDATE HANSIP_GROUP SET GROUP_NAME=?, DESCRIPTION=? WHERE REC_ID=?",
			group.GroupName, group.Description, group.RecID)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
		}
		return err
	}
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_GROUP(REC_ID,GROUP_NAME,DESCRIPTION) VALUES(?,?,?)",
		group.RecID, group.GroupName, group.Description)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetGroupRole get GroupRole relation
func (db *MySQLDB) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := mysqlLog.WithField("func", "GetGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) CNT FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=? AND ROLE_REC_ID=?", group.RecID, role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got %s", err.Error())
		return nil, err
	}
	return &GroupRole{
		GroupRecID: group.RecID,
		RoleRecID:  role.RecID,
	}, nil
}

// CreateGroupRole create new Group and Role relation
func (db *MySQLDB) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := mysqlLog.WithField("func", "CreateGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_GROUP_ROLE(GROUP_REC_ID, ROLE_REC_ID) VALUES (?,?)", group.RecID, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		return nil, err
	}
	return &GroupRole{
		GroupRecID: group.RecID,
		RoleRecID:  role.RecID,
	}, nil
}

// ListGroupRoleByGroup list all role related to a group
func (db *MySQLDB) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListGroupRoleByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=?", group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID, R.ROLE_NAME, R.DESCRIPTION FROM HANSIP_GROUP_ROLE UR, HANSIP_ROLE R WHERE UR.ROLE_REC_ID = R.REC_ID AND UR.GROUP_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Role, 0)
	rows, err := db.instance.QueryContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		role := &Role{}
		err := rows.Scan(&role.RecID, &role.RoleName, &role.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			ret = append(ret, role)
		}
	}
	return ret, page, nil
}

// ListGroupRoleByRole will list all group- related to a role
func (db *MySQLDB) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListGroupRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_GROUP_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID, R.GROUP_NAME, R.DESCRIPTION FROM HANSIP_GROUP_ROLE UR, HANSIP_GROUP R WHERE UR.GROUP_REC_ID = R.REC_ID AND UR.ROLE_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Group, 0)
	rows, err := db.instance.QueryContext(ctx, q, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		group := &Group{}
		err := rows.Scan(&group.RecID, &group.GroupName, &group.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			ret = append(ret, group)
		}
	}
	return ret, page, nil
}

// DeleteGroupRole delete a group-role relation
func (db *MySQLDB) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=? AND ROLE_REC_ID=?", groupRole.GroupRecID, groupRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteGroupRoleByGroup deletes group-role relation by the group
func (db *MySQLDB) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRoleByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteGroupRoleByRole deletes grou[-role relation by the role
func (db *MySQLDB) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRoleByRole").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetUserGroup list all user-group relation
func (db *MySQLDB) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := mysqlLog.WithField("func", "GetUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) CNT FROM HANSIP_USER_GROUP WHERE USER_REC_ID=? AND GROUP_REC_ID=?", user.RecID, group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, err
	}
	return &UserGroup{
		GroupRecID: group.RecID,
		UserRecID:  user.RecID,
	}, nil
}

// CreateUserGroup create new relation between user and group
func (db *MySQLDB) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := mysqlLog.WithField("func", "CreateUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_USER_GROUP(USER_REC_ID, GROUP_REC_ID) VALUES (?,?)", user.RecID, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		return nil, err
	}
	return &UserGroup{
		UserRecID:  user.RecID,
		GroupRecID: group.RecID,
	}, nil
}

// ListUserGroupByUser will list groups that related to a user
func (db *MySQLDB) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserGroupByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_USER_GROUP WHERE USER_REC_ID=?", user.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("row.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID, R.GROUP_NAME, R.DESCRIPTION FROM HANSIP_USER_GROUP UR, HANSIP_GROUP R WHERE UR.GROUP_REC_ID = R.REC_ID AND UR.USER_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*Group, 0)
	rows, err := db.instance.QueryContext(ctx, q, user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		group := &Group{}
		err := rows.Scan(&group.RecID, &group.GroupName, &group.Description)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			ret = append(ret, group)
		}
	}
	return ret, page, nil
}

// ListUserGroupByGroup will list all users that related to a group
func (db *MySQLDB) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserGroupByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	row := db.instance.QueryRowContext(ctx, "SELECT COUNT(*) FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=?", group.RecID)
	count := 0
	err := row.Scan(&count)
	if err != nil {
		fLog.Errorf("rows.Scan got  %s", err.Error())
		return nil, nil, err
	}
	page := helper.NewPage(request, uint(count))
	q := fmt.Sprintf("SELECT R.REC_ID,R.EMAIL,R.HASHED_PASSPHRASE,R.ENABLED, R.SUSPENDED,R.LAST_SEEN,R.LAST_LOGIN,R.FAIL_COUNT,R.ACTIVATION_CODE,R.ACTIVATION_DATE,R.TOTP_KEY,R.ENABLE_2FE,R.TOKEN_2FE,R.RECOVERY_CODE FROM HANSIP_USER_GROUP UR, HANSIP_USER R WHERE UR.USER_REC_ID = R.REC_ID AND UR.GROUP_REC_ID = ? ORDER BY R.%s %s LIMIT %d, %d", request.OrderBy, request.Sort, page.OffsetStart, page.OffsetEnd-page.OffsetStart)
	ret := make([]*User, 0)
	rows, err := db.instance.QueryContext(ctx, q, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.QueryContext got  %s", err.Error())
		return nil, nil, err
	}
	for rows.Next() {
		user := &User{}
		var enabled, suspended, enable2fa int
		err := rows.Scan(&user.RecID, &user.Email, &user.HashedPassphrase, &enabled, &suspended, &user.LastSeen, &user.LastLogin, &user.FailCount, &user.ActivationCode,
			&user.ActivationDate, &user.UserTotpSecretKey, &enable2fa, &user.Token2FA, &user.RecoveryCode)
		if err != nil {
			fLog.Warnf("rows.Scan got  %s", err.Error())
		} else {
			if enabled == 1 {
				user.Enabled = true
			}
			if suspended == 1 {
				user.Suspended = true
			}
			if enable2fa == 1 {
				user.Enable2FactorAuth = true
			}
			ret = append(ret, user)
		}
	}
	return ret, page, nil
}

// DeleteUserGroup will delete a user-group
func (db *MySQLDB) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=? AND USER_REC_ID=?", userGroup.GroupRecID, userGroup.UserRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// DeleteUserGroupByUser will delete a user-group relation by a user
func (db *MySQLDB) DeleteUserGroupByUser(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroupByUser").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE USER_REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// DeleteUserGroupByGroup will delete user-group relation by a group
func (db *MySQLDB) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroupByGroup").WithField("RequestID", ctx.Value(constants.RequestID))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}
