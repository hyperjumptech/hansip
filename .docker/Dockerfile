FROM golang:1.13
ENV GOPATH /go
ENV GO111MODULE on
ENV GOOS linux
ENV GOARCH amd64

RUN go get -v github.com/rubenv/sql-migrate/...
RUN sql-migrate --help
