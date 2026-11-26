include versions.mk

ifeq ($(SAN),1)
FLAVOR  := -san
CC_OPT  := -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -DNGX_DEBUG_PALLOC=1
LD_OPT  := -fsanitize=address,undefined
SAN_ENV := -e ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=0:log_path=/tmp/sundew/san/asan \
           -e UBSAN_OPTIONS=print_stacktrace=1:log_path=/tmp/sundew/san/ubsan
else
CC_OPT  := -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -fstack-protector-strong
LD_OPT  :=
endif

IMAGE   := sundew-dev:nginx-$(NGINX_VERSION)$(FLAVOR)
VOLUME  := sundew-work-$(NGINX_VERSION)$(FLAVOR)
RUN      = docker run --rm --init --cap-add NET_ADMIN $(SAN_ENV) \
             -v $(CURDIR):/src:ro -v $(VOLUME):/work $(1) $(IMAGE)

.PHONY: image build unit fmt lint test test-async test-features test-all test-long test-pid1 release-image test-image artifacts docs docs-build docs-site shell clean

image:
	docker build -f docker/Dockerfile --target dev \
	    --build-arg NGINX_VERSION=$(NGINX_VERSION) \
	    --build-arg NGINX_SHA256=$(NGINX_SHA256) \
	    --build-arg NGINX_CC_OPT="$(CC_OPT)" --build-arg NGINX_LD_OPT="$(LD_OPT)" \
	    -t $(IMAGE) .

build: image
	$(call RUN) /src/docker/build.sh

unit: image
	$(call RUN) sh -c 'cd /src/helper && cargo test --locked'

fmt: image
	$(call RUN) sh -c 'mkdir /tmp/a /tmp/b && cp -r /src/helper /tmp/a/ && cp -r /src/helper /tmp/b/ \
	    && cd /tmp/b/helper && cargo fmt && cd /tmp && diff -ru a b; true' > .fmt.patch
	git apply --allow-empty .fmt.patch && rm .fmt.patch

lint: image
	$(call RUN) sh -c 'cd /src/helper && cargo fmt --check && cargo clippy --locked -- -D warnings'

test: image
	$(call RUN,--cap-add SYS_PTRACE) sh -c '/src/docker/build.sh && /src/tests/lifecycle/run.sh'

test-features: image
	$(call RUN,--cap-add SYS_PTRACE) sh -c '/src/docker/build.sh && /src/tests/features/run.sh'

test-all: image
	$(call RUN,--cap-add SYS_PTRACE) sh -c '/src/docker/build.sh && /src/tests/lifecycle/run.sh && /src/tests/async/run.sh && /src/tests/features/run.sh'

test-async: image
	$(call RUN,--cap-add SYS_PTRACE) sh -c '/src/docker/build.sh && /src/tests/async/run.sh'

test-long: image
	$(call RUN,--cap-add SYS_PTRACE -e RELOADS=1000) sh -c '/src/docker/build.sh && /src/tests/lifecycle/run.sh'

test-pid1: image
	tests/lifecycle/pid1.sh $(IMAGE) $(VOLUME)

# release builds: BASE is an official nginx image or a distribution (DISTRO_NGINX=1)
BASE         ?= nginx:$(NGINX_VERSION)
DISTRO_NGINX ?=
RELEASE_ARGS  = -f docker/release.Dockerfile --build-arg BASE=$(BASE) \
                --build-arg NGINX_VERSION=$(NGINX_VERSION) --build-arg NGINX_SHA256=$(NGINX_SHA256) \
                --build-arg DISTRO_NGINX=$(DISTRO_NGINX)
RELEASE_IMAGE ?= sundew:nginx$(NGINX_VERSION)

release-image:
	docker build $(RELEASE_ARGS) --target image -t $(RELEASE_IMAGE) .

test-image: release-image image
	tests/image/run.sh $(RELEASE_IMAGE) $(IMAGE)

artifacts:
	docker build $(RELEASE_ARGS) --target artifacts --output type=local,dest=dist/$(subst :,-,$(subst /,-,$(BASE))) .

DOCS_RUN = docker run --rm -v $(CURDIR):/src:ro -w /src $(1) python:3.12-slim \
             sh -c 'pip install -q --disable-pip-version-check --root-user-action=ignore -r docs/requirements.txt && $(2)'

docs-build:
	$(call DOCS_RUN,,mkdocs build --strict -d /tmp/site)

docs-site:
	mkdir -p site
	docker run --rm -v $(CURDIR):/src:ro -v $(CURDIR)/site:/site -w /src --user $$(id -u):$$(id -g) \
	    -e HOME=/tmp python:3.12-slim sh -c 'pip install -q --disable-pip-version-check --user \
	    -r docs/requirements.txt && python -m mkdocs build --strict -d /site'

docs:
	$(call DOCS_RUN,-p 127.0.0.1:8000:8000,mkdocs serve -a 0.0.0.0:8000)

shell: image
	docker run --rm -it --init --cap-add NET_ADMIN \
	    -v $(CURDIR):/src:ro -v $(VOLUME):/work $(IMAGE) bash

clean:
	-docker volume rm $(VOLUME)
