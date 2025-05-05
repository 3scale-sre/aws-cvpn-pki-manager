TAG	?= local
IMAGE	?= quay.io/3scale-sre/aws-cvpn-pki-manager
CONTAINER_TOOL ?= podman

.PHONY: help
help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null \
		| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
		| egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort


# MULTI-PLATFORM BUILD/PUSH FUNCTIONS
# NOTE IF USING DOCKER (https://docs.docker.com/build/building/multi-platform/#prerequisites):
#   The "classic" image store of the Docker Engine does not support multi-platform images.
#   Switching to the containerd image store ensures that your Docker Engine can push, pull,
#   and build multi-platform images.

# container-build-multiplatform will build a multiarch image using the defined container tool
# $1 - image tag
# $2 - container tool: docker/podman
# $3 - dockerfile path
# $4 - build context path
# $5 - platforms
define container-build-multiplatform
@{\
set -e; \
echo "Building $1 for $5 using $2"; \
if [ "$2" = "docker" ]; then \
	docker buildx build --platform $5 -f $3 --tag $1 $4; \
elif [ "$2" = "podman" ]; then \
	podman build --platform $5 -f $3 --manifest $1 $4; \
else \
	echo "unknown container tool $2"; exit -1; \
fi \
}
endef

# container-push-multiplatform will push a multiarch image using the defined container tool
# $1 - image tag
# $2 - container tool: docker/podman
define container-push-multiplatform
@{\
set -e; \
echo "Pushing $1 using $2"; \
if [ "$2" = "docker" ]; then \
	docker push $1; \
elif [ "$2" = "podman" ]; then \
	podman manifest push --all $1; \
else \
	echo "unknown container tool $2"; exit -1; \
fi \
}
endef

# LOCAL PLATFORM BUILD
.PHONY: container-build
container-build:
	$(call container-build-multiplatform,$(IMAGE):$(TAG),$(CONTAINER_TOOL),Dockerfile,.,$(shell go env GOARCH))

.PHONY: container-push
container-push:
	$(call container-push-multiplatform,$(IMAGE):$(TAG),$(CONTAINER_TOOL))

# MULTI-PLATFORM BUILD/PUSH
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: container-buildx
container-buildx: ## cross-platfrom build
	$(call container-build-multiplatform,$(IMAGE):$(TAG),$(CONTAINER_TOOL),Dockerfile,.,$(PLATFORMS))

.PHONY: container-pushx
container-pushx:
	$(call container-push-multiplatform,$(IMAGE):$(TAG),$(CONTAINER_TOOL))

# Dev Vault server
VAULT_RELEASE = 1.19
TEST_IMAGE = mirror.gcr.io/library/debian:bookworm-slim
TF_CMD := $(CONTAINER_TOOL) run --rm -ti -v $$(pwd):/work -w /work --privileged --network host docker.io/hashicorp/terraform:light
vault-up:
	$(CONTAINER_TOOL) run --cap-add=IPC_LOCK -d --network host --name=dev-vault -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' docker.io/hashicorp/vault:$(VAULT_RELEASE)
	cd test/tf-dataset1 && \
		$(TF_CMD) init && \
		$(TF_CMD) apply --auto-approve
vault-down:
	$(CONTAINER_TOOL) rm -f $$($(CONTAINER_TOOL) ps -aqf "name=dev-vault")
	find test/ -type f -name "*.tfstate*" -exec rm -f {} \;

# Dev ACPM server
ACPM_CMD := $(CONTAINER_TOOL) run --network host -d --name=dev-acpm -v $$(pwd):/work -w $(TEST_IMAGE) build/aws-cvpn-pki-manager_amd64_$(ACPM_RELEASE) server
acpm-up: container-build
	$(CONTAINER_TOOL) run --network host -d --name=dev-acpm $(IMAGE):$(TAG) \
		--vault-auth-token myroot --client-vpn-endpoint-id "placeholder" --vault-pki-paths pki
acpm-down:
	$(CONTAINER_TOOL) rm -f $$($(CONTAINER_TOOL) ps -aqf "name=dev-acpm")

dev-up: vault-up acpm-up
dev-down: acpm-down vault-down

test: dev-up
	$(CONTAINER_TOOL) run --rm -ti --network host --privileged --name=curl-runnings -v $$(pwd):/work -w /work $(TEST_IMAGE) test/run-integration-tests.sh
	$(MAKE) dev-down
