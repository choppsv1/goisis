
all:
	go install -gcflags=all="-N -l" ./...
	if [ $$(uname -s) != "Darwin" ]; then sudo setcap cap_net_raw=pe ~/go/bin/goisis; fi

.PHONY: docker

docker:
	docker build -f docker/Dockerfile.isisd -t choppsv1/isisd docker
