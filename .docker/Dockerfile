FROM golang:1.13
ENV GOPATH /go
ENV GO111MODULE on
ENV GOOS linux
ENV GOARCH amd64

# Prepare all the dirs.
RUN mkdir -p $GOPATH/src/github.com/hyperjumptech/hansip
RUN mkdir -p $GOPATH/src/github.com/newm4n
# Copy the build content.
COPY . $GOPATH/src/github.com/hyperjumptech/hansip
# Checkout the go-resource to auto generate statics into go codes.
WORKDIR $GOPATH/src/github.com/newm4n
RUN git clone https://github.com/newm4n/go-resource.git
# Compile the go-resource
WORKDIR $GOPATH/src/github.com/newm4n/go-resource
RUN go build -o go-resource.app *.go
# Create the statics code using go-resource
WORKDIR $GOPATH/src/github.com/hyperjumptech/hansip
RUN $GOPATH/src/github.com/newm4n/go-resource/go-resource.app  -base "$GOPATH/src/github.com/hyperjumptech/hansip/api/swagger-ui" -path "/docs" -filter "/**/*" -go "$GOPATH/src/github.com/hyperjumptech/hansip/api/StaticApi.go" -package api
# Compile the proje ct
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o hansip.app cmd/Main.go

# Now use the deployment image.
FROM alpine:latest
ENV GOPATH /go
RUN apk --no-cache add ca-certificates
# Copy the built binary to the new image.
WORKDIR /root/
COPY --from=0 $GOPATH/src/github.com/hyperjumptech/hansip/hansip.app .
# Expose port.
EXPOSE 3000
# Execute
CMD ["./hansip.app"]