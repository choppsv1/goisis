
all:
	go install -gcflags=all="-N -l" ./...
	sudo setcap cap_net_raw=pe ~/go/bin/goisis

.PHONY: docker

docker:
	docker build -f docker/Dockerfile.isisd -t choppsv1/isisd docker
