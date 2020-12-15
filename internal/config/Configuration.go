package config

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"strconv"
	"strings"
)

var (
	defCfg      map[string]string
	initialized = false
)

// initialize this configuration
func initialize() {
	viper.SetEnvPrefix("aaa")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	defCfg = make(map[string]string)

	defCfg["api.path.prefix"] = "/api/v1"

	defCfg["server.host"] = "localhost"
	defCfg["server.port"] = "3000"
	defCfg["server.log.level"] = "warn" // valid values are trace, debug, info, warn, error, fatal
	defCfg["server.timeout.write"] = "15 seconds"
	defCfg["server.timeout.read"] = "15 seconds"
	defCfg["server.timeout.idle"] = "60 seconds"
	defCfg["server.timeout.graceshut"] = "15 seconds"
	defCfg["server.http.cors.enable"] = "true"
	defCfg["server.http.cors.allow.origins"] = "*"
	defCfg["server.http.cors.allow.credential"] = "true"
	defCfg["server.http.cors.allow.method"] = "GET,PUT,DELETE,POST,OPTIONS"
	defCfg["server.http.cors.allow.headers"] = "Accept,Authorization,Content-Type,X-CSRF-TOKEN,Accept-Encoding,X-Forwarded-For,X-Real-IP,X-Request-ID"
	defCfg["server.http.cors.exposed.headers"] = "*"
	defCfg["server.http.cors.optionpassthrough"] = "true"
	defCfg["server.http.cors.maxage"] = "300"

	defCfg["token.issuer"] = "aaa.domain.com"
	defCfg["token.access.duration"] = "5 minutes"
	defCfg["token.refresh.duration"] = "1 year"

	defCfg["token.crypt.key"] = "th15mustb3CH@ngedINprodUCT10N"
	defCfg["token.crypt.method"] = "HS512"

	defCfg["db.type"] = "MYSQL" // INMEMORY, MYSQL
	defCfg["db.mysql.host"] = "localhost"
	defCfg["db.mysql.port"] = "3306"
	defCfg["db.mysql.user"] = "devuser"
	defCfg["db.mysql.password"] = "devpassword"
	defCfg["db.mysql.database"] = "devdb"
	defCfg["db.mysql.maxidle"] = "3"
	defCfg["db.mysql.maxopen"] = "10"

	defCfg["hansip.domain"] = "hansip"
	defCfg["hansip.admin"] = "admin"

	defCfg["security.passphrase.minchars"] = "8"
	defCfg["security.passphrase.minwords"] = "3"
	defCfg["security.passphrase.mincharsinword"] = "3"

	defCfg["mailer.type"] = "SENDGRID" // DUMMY, SENDMAIL, SENDGRID
	defCfg["mailer.from"] = "hansip@aaa.com"
	defCfg["mailer.from.name"] = "hansip@aaa.com"
	defCfg["mailer.sendmail.host"] = "localhost"
	defCfg["mailer.sendmail.port"] = "25"
	defCfg["mailer.sendmail.user"] = "sendmail"
	defCfg["mailer.sendmail.password"] = "password"
	defCfg["mailer.templates.emailveri.subject"] = "Please verify your new Hansip account's email"
	defCfg["mailer.templates.emailveri.body"] = "<html><body>Dear New Hansip User<br><br>Your new account is ready!<br>please click this <a href=\"http://172.31.219.130:3001/activate?email={{.Email}}&code={{.ActivationCode}}\">link to activate</a> your account.<br><br>Cordially,<br>HANSIP team</body></html>"
	defCfg["mailer.templates.passrecover.subject"] = "Passphrase recovery instruction"
	defCfg["mailer.templates.passrecover.body"] = "<html><body>Dear Hansip User<br><br>To recover your passphrase<br>please click this <a href=\"http://172.31.219.130:3001/recover?email={{.Email}}&code={{.RecoveryCode}}\">link to change your passphrase</a>.<br><br>Cordially,<br>HANSIP team</body></html>"
	defCfg["mailer.sendgrid.token"] = "SENDGRIDTOKEN"

	for k := range defCfg {
		err := viper.BindEnv(k)
		if err != nil {
			log.Errorf("Failed to bind env \"%s\" into configuration. Got %s", k, err)
		}
	}

	initialized = true
}

// SetConfig put configuration key value
func SetConfig(key, value string) {
	viper.Set(key, value)
}

// Get fetch configuration as string value
func Get(key string) string {
	if !initialized {
		initialize()
	}
	ret := viper.GetString(key)
	if len(ret) == 0 {
		if ret, ok := defCfg[key]; ok {
			return ret
		}
		log.Debugf("%s config key not found", key)
	}
	return ret
}

// GetBoolean fetch configuration as boolean value
func GetBoolean(key string) bool {
	if len(Get(key)) == 0 {
		return false
	}
	b, err := strconv.ParseBool(Get(key))
	if err != nil {
		panic(err)
	}
	return b
}

// GetInt fetch configuration as integer value
func GetInt(key string) int {
	if len(Get(key)) == 0 {
		return 0
	}
	i, err := strconv.ParseInt(Get(key), 10, 64)
	if err != nil {
		panic(err)
	}
	return int(i)
}

// GetFloat fetch configuration as float value
func GetFloat(key string) float64 {
	if len(Get(key)) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(Get(key), 64)
	if err != nil {
		panic(err)
	}
	return f
}

// Set configuration key value
func Set(key, value string) {
	defCfg[key] = value
}
