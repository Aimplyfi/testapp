.PHONY: all client server

all: client server

client:
	cd client && make build

server:
	cd server && make build

deploy:
	kubectl apply -f namespace-security.yaml
	kubectl apply -f rbac-policies.yaml
	kubectl apply -f network-policies.yaml
	kubectl apply -f server.yaml
	kubectl apply -f client.yaml
