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
	$(MAKE) buildx PLATFORMS=$(shell go env GOARCH)

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
	PUSHX_CMD = manifest push --all $(IMAGE):$(TAG)
endif
.PHONY: buildx
buildx: ## cross-platfrom build 
	$(CONTAINER_RUNTIME) $(BUILDX_CMD)

.PHONY: pushx
pushx:
	$(CONTAINER_RUNTIME) $(PUSHX_CMD)

# Dev Vault server
VAULT_RELEASE = 1.19
TEST_IMAGE = mirror.gcr.io/library/debian:bookworm-slim
TF_CMD := $(CONTAINER_RUNTIME) run --rm -ti -v $$(pwd):/work -w /work --privileged --network host docker.io/hashicorp/terraform:light
vault-up:
	$(CONTAINER_RUNTIME) run --cap-add=IPC_LOCK -d --network host --name=dev-vault -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' docker.io/hashicorp/vault:$(VAULT_RELEASE)
	cd test/tf-dataset1 && \
		$(TF_CMD) init && \
		$(TF_CMD) apply --auto-approve
vault-down:
	$(CONTAINER_RUNTIME) rm -f $$($(CONTAINER_RUNTIME) ps -aqf "name=dev-vault")
	find test/ -type f -name "*.tfstate*" -exec rm -f {} \;

# Dev ACPM server
ACPM_CMD := $(CONTAINER_RUNTIME) run --network host -d --name=dev-acpm -v $$(pwd):/work -w $(TEST_IMAGE) build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE) server
acpm-up: build
	$(CONTAINER_RUNTIME) run --network host -d --name=dev-acpm $(IMAGE):$(TAG) \
		--vault-auth-token myroot --client-vpn-endpoint-id "placeholder" --vault-pki-paths pki
acpm-down:
	$(CONTAINER_RUNTIME) rm -f $$($(CONTAINER_RUNTIME) ps -aqf "name=dev-acpm")

dev-up: vault-up acpm-up
dev-down: acpm-down vault-down

test: dev-up
	$(CONTAINER_RUNTIME) run --rm -ti --network host --privileged --name=curl-runnings -v $$(pwd):/work -w /work $(TEST_IMAGE) test/run-integration-tests.sh
	$(MAKE) dev-down
