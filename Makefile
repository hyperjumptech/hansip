GOPATH=$(shell go env GOPATH)
IMAGE_REGISTRY=dockerhub
IMAGE_NAMESPACE ?= hansip
IMAGE_NAME ?= $(shell basename `pwd`)
CURRENT_PATH=$(shell pwd)
COMMIT_ID ?= $(shell git rev-parse --short HEAD)
GO111MODULE=on

.PHONY: all test clean build docker

build-static:
	-${GOPATH}/bin/go-resource -base "$(CURRENT_PATH)/api/swagger-ui" -path "/docs" -filter "/**/*" -go "$(CURRENT_PATH)/api/StaticApi.go" -package api
	go fmt ./...

build: build-static
#	export GO111MODULE=on; \
#	GO_ENABLED=0 go build -a -o $(IMAGE_NAME).app cmd/main/Main.go
#   Use bellow if you're running on linux.
	GO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(IMAGE_NAME).app cmd/main/Main.go

lint: build-static
#	golint -set_exit_status ./internal/... ./pkg/... ./cmd/...

test: lint
#	go install github.com/newm4n/goornogo
	export GO111MODULE on; \
	go test ./... -cover -vet -all -v -short -covermode=count -coverprofile=coverage.out
#	goornogo -i coverage.out -c 30

run: build
	export AAA_SERVER_HOST=0.0.0.0; \
	export AAA_SERVER_PORT=8088; \
	export AAA_SETUP_ADMIN_ENABLE=true; \
	export AAA_SERVER_LOG_LEVEL=TRACE; \
	export AAA_SERVER_HTTP_CORS_ENABLE=true; \
	export AAA_SERVER_HTTP_CORS_ALLOW_ORIGINS=*; \
	export AAA_SERVER_HTTP_CORS_ALLOW_CREDENTIAL=true; \
	export AAA_SERVER_HTTP_CORS_ALLOW_METHOD=GET,PUT,DELETE,POST,OPTIONS; \
	export AAA_SERVER_HTTP_CORS_ALLOW_HEADERS=Accept,Authorization,Content-Type,X-CSRF-TOKEN,Accept-Encoding; \
	export AAA_SERVER_HTTP_CORS_EXPOSED_HEADERS=*; \
	export AAA_SERVER_HTTP_CORS_IGNOREOPTION=false; \
	export AAA_SERVER_HTTP_CORS_OPTIONSTATUS=200; \
	export AAA_TOKEN_ISSUER=aaa.hansip.go.id; \
	export AAA_DB_TYPE=INMEMORY; \
	export AAA_MAILER_TYPE=DUMMY; \
	export AAA_MAILER_FROM=aaa@hansip.go.id; \
	export AAA_MAILER_SENDMAIL_HOST=hansip.go.id; \
	export AAA_MAILER_SENDMAIL_PORT=25; \
	export AAA_MAILER_SENDMAIL_USER=user; \
	export AAA_MAILER_SENDMAIL_PASSWORD=password; \
	./$(IMAGE_NAME).app
	rm -f $(IMAGE_NAME).app

docker:
	docker build -t $(IMAGE_NAMESPACE)/$(IMAGE_NAME):latest -f ./.docker/Dockerfile .

docker-build-commit: build
	docker build -t $(IMAGE_NAMESPACE)/$(IMAGE_NAME):$(COMMIT_ID) -f ./.docker/Dockerfile .

docker-build: build
	docker build -t $(IMAGE_NAMESPACE)/$(IMAGE_NAME):$(COMMIT_ID) -f ./.docker/Dockerfile .
	docker tag $(IMAGE_NAMESPACE)/$(IMAGE_NAME):$(COMMIT_ID) $(IMAGE_NAMESPACE)/$(IMAGE_NAME):latest

docker-push:
	docker push $(IMAGE_NAMESPACE)/$(IMAGE_NAME):$(COMMIT_ID)

docker-stop:
	-docker stop $(IMAGE_NAME)

docker-rm: docker-stop
	-docker rm $(IMAGE_NAME)

docker-run: docker-rm docker
	docker run --name $(IMAGE_NAME) -p 3000:3000 --detach $(IMAGE_NAMESPACE)/$(IMAGE_NAME):latest
