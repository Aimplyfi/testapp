.PHONY: all client server

all: client server

client:
	cd client && make build

server:
	cd server && make build
