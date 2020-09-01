package connector

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hyperjumptech/hansip/internal/config"
	"github.com/hyperjumptech/hansip/internal/constants"
	"github.com/hyperjumptech/hansip/pkg/helper"
	"github.com/hyperjumptech/hansip/pkg/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	DROP_ALL    = `DROP TABLE IF EXISTS HANSIP_USER_GROUP, HANSIP_USER_ROLE, HANSIP_GROUP_ROLE, HANSIP_USER, HANSIP_GROUP, HANSIP_ROLE;`
	CREATE_USER = `CREATE TABLE IF NOT EXISTS HANSIP_USER (
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
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	CREATE_GROUP = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    GROUP_NAME VARCHAR(128) NOT NULL UNIQUE,
    DESCRIPTION VARCHAR(255),
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	CREATE_ROLE = `CREATE TABLE IF NOT EXISTS HANSIP_ROLE (
    REC_ID VARCHAR(32) NOT NULL UNIQUE,
    ROLE_NAME VARCHAR(128) NOT NULL UNIQUE,
    DESCRIPTION VARCHAR(255),
    PRIMARY KEY (REC_ID)
) ENGINE=INNODB;`
	CREATE_USER_ROLE = `CREATE TABLE IF NOT EXISTS HANSIP_USER_ROLE (
    USER_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
	CREATE_USER_GROUP = `CREATE TABLE IF NOT EXISTS HANSIP_USER_GROUP (
    USER_REC_ID VARCHAR(32) NOT NULL,
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (USER_REC_ID,GROUP_REC_ID),
    FOREIGN KEY (USER_REC_ID) REFERENCES HANSIP_USER(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
	CREATE_GROUP_ROLE = `CREATE TABLE IF NOT EXISTS HANSIP_GROUP_ROLE (
    GROUP_REC_ID VARCHAR(32) NOT NULL,
    ROLE_REC_ID VARCHAR(32) NOT NULL,
    PRIMARY KEY (GROUP_REC_ID,ROLE_REC_ID),
    FOREIGN KEY (GROUP_REC_ID) REFERENCES HANSIP_GROUP(REC_ID) ON DELETE CASCADE,
    FOREIGN KEY (ROLE_REC_ID) REFERENCES HANSIP_ROLE(REC_ID) ON DELETE CASCADE
) ENGINE=INNODB;`
)

var (
	mysqlLog        = log.WithField("go", "MySqlDbConnector")
	mySQLDbInstance *MySQLDB
)

// GetMySQLDBInstance initializes the MySQL.DB instance
func GetMySQLDBInstance() *MySQLDB {
	if mySQLDbInstance == nil {
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
		mySQLDbInstance = &MySQLDB{
			instance: db,
		}
	}
	return mySQLDbInstance
}

// MySQLDB type
type MySQLDB struct {
	instance *sql.DB
}

// DropAllTables will drop all tables used by Hansip
func (db *MySQLDB) DropAllTables(ctx context.Context) error {
	_, err := db.instance.ExecContext(ctx, DROP_ALL)
	if err != nil {
		mysqlLog.WithField("func", "DropAllTables").WithField("RequestId", ctx.Value(constants.RequestId)).Errorf("got %s", err.Error())
	}
	return err
}

// CreateAllTable creates all table used by Hansip
func (db *MySQLDB) CreateAllTable(ctx context.Context) error {
	fLog := mysqlLog.WithField("func", "CreateAllTable").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, CREATE_USER)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CREATE_GROUP)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CREATE_ROLE)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_ROLE Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CREATE_USER_ROLE)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_ROLE Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CREATE_USER_GROUP)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_USER_GROUP Got %s", err.Error())
	}
	_, err = db.instance.ExecContext(ctx, CREATE_GROUP_ROLE)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext HANSIP_GROUP_ROLE Got %s", err.Error())
	}
	return err
}

// GetUserByRecID get user data by its RecID
func (db *MySQLDB) GetUserByRecID(ctx context.Context, recID string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserByRecID").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "CreateUserRecord").WithField("RequestId", ctx.Value(constants.RequestId))
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
		UserTotpSecretKey: totp.MakeRandomTotpKey(),
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

// GetUserByEmail get user record by its email address
func (db *MySQLDB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	fLog := mysqlLog.WithField("func", "GetUserByEmail").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "GetUserBy2FAToken").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "GetUserByRecoveryToken").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "DeleteUser").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER WHERE REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// IsUserRecIdExist check if a specific user recId is exist in database
func (db *MySQLDB) IsUserRecIdExist(ctx context.Context, recId string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsUserRecIdExist").WithField("RequestId", ctx.Value(constants.RequestId))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_USER WHERE REC_ID=?", recId)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsUserRecIdExist cant scan")
	return false, fmt.Errorf("db.instance.IsUserRecIdExist cant scan")
}

// SaveOrUpdate save or update a user data
func (db *MySQLDB) SaveOrUpdate(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdate").WithField("RequestId", ctx.Value(constants.RequestId))
	creating, err := db.IsUserRecIdExist(ctx, user.RecID)
	if err != nil {
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
	if creating {
		_, err = db.instance.ExecContext(ctx, "INSERT INTO HANSIP_USER(REC_ID,EMAIL,HASHED_PASSPHRASE,ENABLED, SUSPENDED,LAST_SEEN,LAST_LOGIN,FAIL_COUNT,ACTIVATION_CODE,ACTIVATION_DATE,TOTP_KEY,ENABLE_2FE,TOKEN_2FE,RECOVERY_CODE) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
			user.RecID, user.Email, user.HashedPassphrase, enabled, suspended, user.LastSeen, user.LastLogin, user.FailCount, user.ActivationCode,
			user.ActivationDate, user.UserTotpSecretKey, enable2fa, user.Token2FA, user.RecoveryCode)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got %s", err.Error())
		}
		return err
	}
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
	fLog := mysqlLog.WithField("func", "ListUser").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "Count").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "ListAllUserRoles").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "GetUserRole").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "CreateUserRole").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "ListUserRoleByUser").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "ListUserRoleByRole").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "DeleteUserRole").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=? AND ROLE_REC_ID=?", userRole.UserRecID, userRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteUserRoleByUser remove ALL role assigment of a user
func (db *MySQLDB) DeleteUserRoleByUser(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "DeleteUserRoleByUser").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE USER_REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteUserRoleByRole remove all user-role assigment to a role
func (db *MySQLDB) DeleteUserRoleByRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "DeleteUserRoleByRole").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetRoleByRecID return a role with speciffic recID
func (db *MySQLDB) GetRoleByRecID(ctx context.Context, recID string) (*Role, error) {
	fLog := mysqlLog.WithField("func", "GetRoleByRecID").WithField("RequestID", ctx.Value(constants.RequestId))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, ROLE_NAME, DESCRIPTION FROM HANSIP_ROLE WHERE REC_ID=?", recID)
	r := &Role{}
	err := row.Scan(&r.RecID, &r.RoleName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got  %s", err.Error())
	}
	return r, err
}

// CreateRole creates a new role
func (db *MySQLDB) CreateRole(ctx context.Context, roleName, description string) (*Role, error) {
	fLog := mysqlLog.WithField("func", "CreateRole").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "ListRoles").WithField("RequestId", ctx.Value(constants.RequestId))
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
		err := row.Scan(&r.RecID, &r.RoleName, &r.Description)
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
	fLog := mysqlLog.WithField("func", "DeleteRole").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_ROLE WHERE REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// IsRoleRecIdExist check if a speciffic role recId is exist in database
func (db *MySQLDB) IsRoleRecIdExist(ctx context.Context, recId string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsUserRecIdExist").WithField("RequestId", ctx.Value(constants.RequestId))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_ROLE WHERE REC_ID=?", recId)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsRoleRecIdExist cant scan")
	return false, fmt.Errorf("db.instance.IsRoleRecIdExist cant scan")
}

// SaveOrUpdateRole save or update a role record
func (db *MySQLDB) SaveOrUpdateRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdateRole").WithField("RequestId", ctx.Value(constants.RequestId))
	creating := false
	if len(role.RecID) == 0 {
		role.RecID = helper.MakeRandomString(10, true, true, true, false)
		creating = true
	} else {
		create, err := db.IsRoleRecIdExist(ctx, role.RecID)
		if err != nil {
			return err
		}
		creating = create
	}
	if creating {
		_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_ROLE(REC_ID,ROLE_NAME,DESCRIPTION) VALUES(?,?,?)",
			role.RecID, role.RoleName, role.Description)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
		}
		return err
	}
	_, err := db.instance.ExecContext(ctx, "UPDATE HANSIP_ROLE SET ROLE_NAME=?, DESCRIPTION=? WHERE REC_ID=?",
		role.RoleName, role.Description, role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetGroupByRecID return a Group data by its RedID
func (db *MySQLDB) GetGroupByRecID(ctx context.Context, recID string) (*Group, error) {
	fLog := mysqlLog.WithField("func", "GetGroupByRecID").WithField("RequestID", ctx.Value(constants.RequestId))
	row := db.instance.QueryRowContext(ctx, "SELECT REC_ID, GROUP_NAME, DESCRIPTION FROM HANSIP_GROUP WHERE REC_ID=?", recID)
	r := &Group{}
	err := row.Scan(&r.RecID, &r.GroupName, &r.Description)
	if err != nil {
		fLog.Errorf("db.instance.QueryRowContext got %s", err.Error())
	}
	return r, err
}

// CreateGroup create new Group
func (db *MySQLDB) CreateGroup(ctx context.Context, groupName, description string) (*Group, error) {
	fLog := mysqlLog.WithField("func", "CreateGroup").WithField("RequestId", ctx.Value(constants.RequestId))
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
	fLog := mysqlLog.WithField("func", "ListGroups").WithField("RequestId", ctx.Value(constants.RequestId))
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
		err := row.Scan(&r.RecID, &r.GroupName, &r.Description)
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
	fLog := mysqlLog.WithField("func", "DeleteGroup").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP WHERE REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// IsGroupRecIdExist check if a speciffic group recId is exist in database
func (db *MySQLDB) IsGroupRecIdExist(ctx context.Context, recId string) (bool, error) {
	fLog := mysqlLog.WithField("func", "IsGroupRecIdExist").WithField("RequestId", ctx.Value(constants.RequestId))
	rows, err := db.instance.QueryContext(ctx, "SELECT COUNT(*) AS CNT FROM HANSIP_GROUP WHERE REC_ID=?", recId)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	if rows.Next() {
		count := 0
		rows.Scan(&count)
		return count > 0, nil
	}
	fLog.Errorf("db.instance.IsGroupRecIdExist cant scan")
	return false, fmt.Errorf("db.instance.IsGroupRecIdExist cant scan")
}

// SaveOrUpdateGroup delete one specific group
func (db *MySQLDB) SaveOrUpdateGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "SaveOrUpdateGroup").WithField("RequestId", ctx.Value(constants.RequestId))
	creating := false
	if len(group.RecID) == 0 {
		group.RecID = helper.MakeRandomString(10, true, true, true, false)
		creating = true
	} else {
		create, err := db.IsGroupRecIdExist(ctx, group.RecID)
		if err != nil {
			return err
		}
		creating = create
	}
	if creating {
		_, err := db.instance.ExecContext(ctx, "INSERT INTO HANSIP_GROUP(REC_ID,GROUP_NAME,DESCRIPTION) VALUES(?,?,?)",
			group.RecID, group.GroupName, group.Description)
		if err != nil {
			fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
		}
		return err
	}
	_, err := db.instance.ExecContext(ctx, "UPDATE HANSIP_GROUP SET GROUP_NAME=?, DESCRIPTION=? WHERE REC_ID=?",
		group.GroupName, group.Description, group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetGroupRole get GroupRole relation
func (db *MySQLDB) GetGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := mysqlLog.WithField("func", "GetGroupRole").WithField("RequestId", ctx.Value(constants.RequestId))
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

// CreateGroupRole creates a Group Role entry
func (db *MySQLDB) CreateGroupRole(ctx context.Context, group *Group, role *Role) (*GroupRole, error) {
	fLog := mysqlLog.WithField("func", "CreateGroupRole").WithField("RequestId", ctx.Value(constants.RequestId))
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

// ListGroupRoleByGroup list all roles owned by group
func (db *MySQLDB) ListGroupRoleByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*Role, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListGroupRoleByGroup").WithField("RequestId", ctx.Value(constants.RequestId))
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

// ListGroupRoleByRole lists all group-roles by role
func (db *MySQLDB) ListGroupRoleByRole(ctx context.Context, role *Role, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListGroupRoleByRole").WithField("RequestId", ctx.Value(constants.RequestId))
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

// DeleteGroupRole deletes group-role by role id
func (db *MySQLDB) DeleteGroupRole(ctx context.Context, groupRole *GroupRole) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRole").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=? AND ROLE_REC_ID=?", groupRole.GroupRecID, groupRole.RoleRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteGroupRoleByGroup deletes group role by group id
func (db *MySQLDB) DeleteGroupRoleByGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRoleByGroup").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE GROUP_REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// DeleteGroupRoleByRole Deletes Group role by role id
func (db *MySQLDB) DeleteGroupRoleByRole(ctx context.Context, role *Role) error {
	fLog := mysqlLog.WithField("func", "DeleteGroupRoleByRole").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_GROUP_ROLE WHERE ROLE_REC_ID=?", role.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got  %s", err.Error())
	}
	return err
}

// GetUserGroup returns Group and User id where user belongs to
func (db *MySQLDB) GetUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := mysqlLog.WithField("func", "GetUserGroup").WithField("RequestId", ctx.Value(constants.RequestId))
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

// CreateUserGroup creates user group with given user and group id
func (db *MySQLDB) CreateUserGroup(ctx context.Context, user *User, group *Group) (*UserGroup, error) {
	fLog := mysqlLog.WithField("func", "CreateUserGroup").WithField("RequestId", ctx.Value(constants.RequestId))
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

// ListUserGroupByUser list user groups where user id is assigned
func (db *MySQLDB) ListUserGroupByUser(ctx context.Context, user *User, request *helper.PageRequest) ([]*Group, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserGroupByUser").WithField("RequestId", ctx.Value(constants.RequestId))
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

// ListUserGroupByGroup list users assigned to group id
func (db *MySQLDB) ListUserGroupByGroup(ctx context.Context, group *Group, request *helper.PageRequest) ([]*User, *helper.Page, error) {
	fLog := mysqlLog.WithField("func", "ListUserGroupByGroup").WithField("RequestId", ctx.Value(constants.RequestId))
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

// DeleteUserGroup deletes user id from UserGroup
func (db *MySQLDB) DeleteUserGroup(ctx context.Context, userGroup *UserGroup) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroup").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=? AND USER_REC_ID=?", userGroup.GroupRecID, userGroup.UserRecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// DeleteUserGroupByUser deletes from usergroup user id
func (db *MySQLDB) DeleteUserGroupByUser(ctx context.Context, user *User) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroupByUser").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE USER_REC_ID=?", user.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}

// DeleteUserGroupByGroup deletes from user group by group id
func (db *MySQLDB) DeleteUserGroupByGroup(ctx context.Context, group *Group) error {
	fLog := mysqlLog.WithField("func", "DeleteUserGroupByGroup").WithField("RequestId", ctx.Value(constants.RequestId))
	_, err := db.instance.ExecContext(ctx, "DELETE FROM HANSIP_USER_GROUP WHERE GROUP_REC_ID=?", group.RecID)
	if err != nil {
		fLog.Errorf("db.instance.ExecContext got %s", err.Error())
	}
	return err
}
