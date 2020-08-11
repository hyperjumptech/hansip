# Hansip 

An AAA (Access Authentication & Authorization) Service by Hyperjump 

## Building Hansip

Prerequisites:

1. Golang 1.13
2. Make utility

**Step 1 Checkout and Install Go-Resource**

```.bash
$ git clone https://github.com/newm4n/go-resource.git
$ cd go-resource
$ go install
```

**Step 2 Checkout Hansip**

```.bash
$ git clone https://github.com/hyperjumptech/hansip.git
$ cd hansip
```

**Step 3 Build and Run**

```bash
$ make build
```

Running the app will automatically build.

```bash
$ make run
```

## Testing Hansip

```bash
$ make test
``` 

## Configuring Hansip

If you want to run Hansip from the make file using `make run` command, you have to
modify the environment variable in the `run` phase.

```make
run: build
	export AAA_SERVER_HOST=localhost; \
	export AAA_SERVER_PORT=8088; \
	export AAA_SETUP_ADMIN_ENABLE=true; \
	./$(IMAGE_NAME).app
	rm -f $(IMAGE_NAME).app
```

You can change the import env variable.

If you're running from docker, you should modify the environment variable for the running
image.

### Environment Variable Values 

| Variable | Environment Variable | Default | Description |
| -------- | -------------------- | ------- | ----------- |
| server.host| AAA_SERVER_HOST | localhost | The host name to bind. could be `localhost` or `0.0.0.0` |
| server.port| AAA_SERVER_PORT | 3000 | The host port to listen from |
| server.timeout.write| AAA_SERVER_TIMEOUT_WRITE | 15 seconds | Server write timeout |
| server.timeout.read| AAA_SERVER_TIMEOUT_READ | 15 seconds | Server read timeout |
| server.timeout.idle| AAA_SERVER_TIMEOUT_IDLE | 60 seconds | Server connection IDLE timeout |
| server.timeout.graceshut| AAA_SERVER_TIMEOUT_GRACESHUT | 15 seconds | Server grace shutdown timeout |
| setup.admin.enable| AAA_SETUP_ADMIN_ENABLE | false | Enable built in admin account |
| setup.admin.email| AAA_SETUP_ADMIN_EMAIL |admin@hansip | Built in admin email address for authentication |
| setup.admin.passphrase| AAA_SETUP_ADMIN_PASSPHRASE |this must be change in the production | Built in admin password for authentication |
| token.issuer| AAA_TOKE_ISSUER |aaa.domain.com | JWT Token issuer value |
| token.access.duration| AAA_ACCESS_DURATION |5 minutes | JWT Access token lifetime |
| token.refresh.duration| AAA_REFRESH_DURATION |1 year | JWT Refresh token lifetime |
| token.crypt.key| AAA_TOKEN_CRYPT_KEY |th15mustb3CH@ngedINprodUCT10N | JWT token crypto key |
| token.crypt.method| AAA_TOKEN_CRYPT_METHOD |HS512 | JWT token crypto method |
| db.type| AAA_DB_TYPE | INMEMORY | Database type. `INMEMORY` or `MYSQL` |
| db.mysql.host| AAA_DB_MYSQL_HOST |localhost | MySQL host |
| db.mysql.port| AAA_DB_MYSQL_PORT |3306 | MySQL Port |
| db.mysql.user| AAA_DB_MYSQL_USER |user | MySQL User to login |
| db.mysql.password| AAA_DB_MYSQL_PASSWORD |password | MySQL Password to login |
| db.mysql.database| AAA_DB_MYSQL_DATABASE |hansip | MySQL Database to use |
| db.mysql.maxidle| AAA_DB_MYSQL_MAXIDLE |3 | Maximum connection that can IDLE  |
| db.mysql.maxopen| AAA_DB_MYSQL_MAXOPEN |10 | Maximum open connection in the pool |
| mailer.type| AAA_MAILER_TYPE | DUMMY | Mailer type. `DUMMY` or `SENDMAIL` |
| mailer.from| AAA_MAILER_FROM |hansip@aaa.com | The email from field |
| mailer.sendmail.host| AAA_MAILER_SENDMAIL_HOST |localhost | Mail server host |
| mailer.sendmail.port| AAA_MAILER_SENDMAIL_PORT |25 | Mail server port |
| mailer.sendmail.user| AAA_MAILER_SENDMAIL_USER |sendmail | Mail server user for authentication |
| mailer.sendmail.password| AAA_MAILER_SENDMAIL_PASSWORD |password | Mail server password for authentication |
| mailer.templates.emailveri.subject| AAA_MAILER_TEMPLATES_EMAILVERI_SUBJECT |Please verify your new Hansip account's email | Email verification subject template |
| mailer.templates.emailveri.body| AAA_MAILER_TEMPLATES_EMAILVERI_BODY | `<html><body>Dear New Hansip User<br><br>Your new account is ready!<br>please click this <a href=\"http://hansip.io/activate?code={{.ActivationCode}}\">link to activate</a> your account.<br><br>Cordially,<br>HANSIP team</body></html>` | Email verification body template |
| mailer.templates.passrecover.subject| AAA_MAILER_TEMPLATES_PASSRECOVER_SUBJECT | Passphrase recovery instruction | Password recovery email subject template |
| mailer.templates.passrecover.body| AAA_MAILER_TEMPLATES_PASSRECOVER_BODY | `<html><body>Dear Hansip User<br><br>To recover your passphrase<br>please click this <a href=\"http://hansip.io/activate?code={{.RecoveryCode}}\">link to change your passphrase</a>.<br><br>Cordially,<br>HANSIP team</body></html>` | Password recovery email body template |
| server.http.cors.enable | AAA_SERVER_HTTP_CORS_ENABLE | true | To enable or disable CORS handling | 
| server.http.cors.allow.origins | AAA_SERVER_HTTP_CORS_ALLOW_ORIGINS | * |  Indicates whether the response can be shared with requesting code from the given origin. | 
| server.http.cors.allow.credential | AAA_SERVER_HTTP_CORS_ALLOW_CREDENTIAL | true | response header tells browsers whether to expose the response to frontend JavaScript code when the request's credentials mode (`Request.credentials`) is `include` | 
| server.http.cors.allow.method | AAA_SERVER_HTTP_CORS_ALLOW_METHOD | GET,PUT,DELETE,POST,OPTIONS | response header specifies the method or methods allowed when accessing the resource in response to a preflight request. | 
| server.http.cors.allow.headers | AAA_SERVER_HTTP_CORS_ALLOW_HEADERS | Accept,Authorization,Content-Type,X-CSRF-TOKEN,Accept-Encoding,X-Forwarded-For,X-Real-IP,X-Request-ID |  response header is used in response to a preflight request which includes the `Access-Control-Request-Headers` to indicate which HTTP headers can be used during the actual request. | 
| server.http.cors.exposed.headers | AAA_SERVER_HTTP_CORS_EXPOSED_HEADERS | * |  response header indicates which headers can be exposed as part of the response by listing their names. | 
| server.http.cors.optionpassthrough | AAA_SERVER_HTTP_CORS_OPTIONPASSTHROUGH | true | Indicates that the OPTIONS method should be handled by server | 
| server.http.cors.maxage | AAA_SERVER_HTTP_CORS_MAXAGE | 300 | response header indicates how long the results of a preflight request (that is the information contained in the `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` headers) can be cached | 

## API Doc

After you have run the server, you can access the API Doc at

[http://localhost:3000/docs/](http://localhost:3000/docs/)