.PHONY: all client server

all: client server publish

client:
	cd client && make build

server:
	cd server && make build

publish:
	kind load docker-image exploit-client:1.0 --name lkc1
	kind load docker-image vuln-server:1.0 --name lkc1

deploy:
	kubectl apply -f manifests/