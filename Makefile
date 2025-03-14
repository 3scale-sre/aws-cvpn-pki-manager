TAG	?= local
IMAGE	?= quay.io/3scale/aws-cvpn-pki-manager
CONTAINER_RUNTIME ?= podman

.PHONY: help
help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null \
		| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
		| egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

# LOCAL PLATFORM BUILD
.PHONY: build
build:
	${CONTAINER_RUNTIME} build --tag $(IMAGE):$(TAG) .

.PHONY: push
push:
	$(CONTAINER_RUNTIME) push $(IMAGE):$(TAG)

# MULTI-PLATFORM BUILD/PUSH
# NOTE IF USING DOCKER (https://docs.docker.com/build/building/multi-platform/#prerequisites):
#   The "classic" image store of the Docker Engine does not support multi-platform images. 
#   Switching to the containerd image store ensures that your Docker Engine can push, pull,
#   and build multi-platform images.
# PLATFORMS defines the target platforms for mult-platform build.
PLATFORMS ?= linux/arm64,linux/amd64
ifeq ($(CONTAINER_RUNTIME),docker)
	BUILDX_CMD = build --platform ${PLATFORMS} --tag $(IMAGE):$(TAG) .
	PUSHX_CMD = push $(IMAGE):$(TAG)
else
	BUILDX_CMD = build --platform ${PLATFORMS} --manifest $(IMAGE):$(TAG) .
	PUSHX_CMD = manifest push $(IMAGE):$(TAG)
endif
.PHONY: buildx
buildx: ## cross-platfrom build 
	$(CONTAINER_RUNTIME) $(BUILDX_CMD)

.PHONY: pushx
pushx:
	$(CONTAINER_RUNTIME) $(PUSHX_CMD)
