default: build
	./xgosumdb -loglevel debug

init: build
	./xgosumdb -loglevel debug -init localhost

build:
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet

check:
	CGO_ENABLED=0 staticcheck

clean:
	CGO_ENABLED=0 go clean

fmt:
	gofmt -w -s *.go
