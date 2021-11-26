# constants
NAME=app
PROJECT?=github.com/MarkoLuna/oauthserver

build:
	go build -o ${NAME} "${PROJECT}/cmd/server"

test:
	go test -race "${PROJECT}/..."

test-cover:
	go test -cover "${PROJECT}/..."

vet:
	go vet "${PROJECT}/..."

test-total-cover:
	go test "${PROJECT}/..." -coverprofile cover.out > /dev/null
	go tool cover -func cover.out
	rm cover.out

run: build
	./app

clean:
	go clean "${PROJECT}/..."
	rm -f ${NAME}
