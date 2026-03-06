# testapp

### Steps to deploy the test in kind cluster

```
make all

kind load docker-image exploit-client:1.0 --name <cluster-name>
kind load docker-image vuln-server:1.0 --name <cluster-name>

make deploy
```