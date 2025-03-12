
.PHONY: help

TAG	?= local
IMAGE	?= quay.io/3scale/aws-cvpn-pki-manager
CONTAINER_TOOL ?= podman

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null \
		| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
		| egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

get-new-release:
	@hack/new-release.sh v$(TAG)

docker-build:
	${CONTAINER_TOOL} build . -t quay.io/3scale/aws-cvpn-pki-manager:v$(TAG) --build-arg release=$(TAG)

# PLATFORMS defines the target platforms for  the manager image be build to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - able to use docker buildx . More info: https://docs.docker.com/build/buildx/
# - have enable BuildKit, More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image for your registry (i.e. if you do not inform a valid value via IMG=<myregistry/image:<tag>> than the export will fail)
# To properly provided solutions that supports more than one platform you should use this option.
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- ${CONTAINER_TOOL} buildx create --name builder
	${CONTAINER_TOOL} buildx use builder
	- ${CONTAINER_TOOL} buildx build --push --platform=$(PLATFORMS) --tag $(IMAGE):$(TAG) -f Dockerfile.cross .
	- ${CONTAINER_TOOL} buildx rm builder
	rm Dockerfile.cross
