CLUSTER=lkc1

.PHONY: all client server

all: client server publish

client:
	cd client && make build

server:
	cd server && make build

publish:
	kind load docker-image exploit-client:1.0 --name $(CLUSTER)
	kind load docker-image vuln-server:1.0 --name $(CLUSTER)

deploy:
	kubectl create ns testns
	kubectl apply -f manifests/namespace-security.yaml
	kubectl apply -f manifests/rbac_policies.yaml
	kubectl apply -f manifests/network_policies.yaml
	kubectl apply -f manifests/cert-init-job.yaml
	sleep 5
	kubectl apply -f manifests/server.yaml
	kubectl apply -f manifests/client.yaml

undeploy:
	kubectl delete --ignore-not-found=true -f manifests/rbac_policies.yaml
	kubectl delete --ignore-not-found=true -f manifests/network_policies.yaml
	kubectl delete --ignore-not-found=true -f manifests/server.yaml
	kubectl delete --ignore-not-found=true -f manifests/client.yaml
	kubectl delete --ignore-not-found=true -f manifests/cert-init-job.yaml
	kubectl delete --ignore-not-found=true -f manifests/namespace-security.yaml

setup:
	 kind create cluster --name $(CLUSTER)
	 sleep 30
	 kubectl get pods -A
	 kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-native.yaml
	 sleep 30
	 kubectl apply -f tests/conf/metallb.conf

cleanup_testbed:
	kind delete cluster --name $(CLUSTER)

client-logs:
	kubectl logs -n testns -l app=exploit-client -f

server-logs:
	kubectl logs -n testns -l app=vuln-server -f