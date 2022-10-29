SHELL:=/bin/bash -o pipefail
MAIN_APP:=lock8
MANAGE_PY:=$(if $(DJANGO_DEBUG),DJANGO_DEBUG=$(DJANGO_DEBUG) ,)python manage.py
MANAGE_SHELL:=$(MANAGE_PY) shell_plus
RUNSERVER_PORT=8000
RUNSERVER_PORT_DOCKER=7979
RUNSERVER_ARGS=$(RUNSERVER_PORT)
MANAGE_RUNSERVER=$(MANAGE_PY) runserver $(RUNSERVER_ARGS)

# This uses https://www.passwordstore.org/, and you should save the
# DATABASE_URL like this: `pass insert lock8/aws/rds/testing`.
DB_TESTING=$(shell pass show lock8/aws/rds/testing)
DB_PROD=$(shell pass show lock8/aws/rds/prod)
DB_PROD_READONLY=$(DB_PROD)
DB_TRACKINGS_TESTING=$(shell pass show lock8/aws/rds/trackings-testing-velodrome)
DB_TRACKINGS_PROD=$(shell pass show lock8/aws/rds/trackings-prod-velodrome)
DB_TRACKINGS_PROD_READONLY=$(DB_TRACKINGS_PROD)

RUN_PYTEST:=python -m pytest
PYTEST_ARGS:=
PYTEST=$(RUN_PYTEST) --nomigrations $(PYTEST_ARGS)

test:
	$(PYTEST)

# Use travis_retry function if it exists.
TRAVIS_RETRY=$(shell declare -f travis_retry >/dev/null && echo travis_retry)

# Run tests on Travis, including integration tests.
# This uses "tee" to make pytest not show progress, e.g. during collection.
test_travis: TEST_DOCKERIMAGE:=0
test_travis:
	$(TRAVIS_RETRY) docker pull tutum/dynamodb >/dev/null
	docker_container="$$(docker run -d -p 9001:8000 tutum/dynamodb)"; \
	  ret=0; \
		$(PYTEST) --run-slow-tests --dynamodb-test-url=http://localhost:9001/ $(if $(CI),| tee,) || ret=$$?; \
	  if [ "$(TEST_DOCKERIMAGE)" = 1 ]; then \
	    make docker_test ENVDIRS=envdir.travis PYTEST_ARGS+="-m test_in_docker -n0 --run-slow-tests" DOCKER_VOLUME_SRC= || ((ret += 32)); \
	    make docker_test_integration || ((ret += 64)); \
	  fi; \
	  docker stop "$$docker_container"; \
	  make check_django || ((ret += 2)); \
	  exit $$ret

check_travis: TEST_MIGRATED:=1
check_travis: TEST_MIGRATIONS:=1
check_travis:
	ret=0; \
	  make check_flake8 || ((ret += 1)); \
	  make check_pycompile || ((ret += 2)); \
	  safety check -r requirements/base.txt || ((ret += 0)); \
	  if [ "$(TEST_MIGRATED)" = 1 ]; then \
	    make check_migrated \
	    && make check_migrated DJANGO_CONFIGURATION=Production || ((ret += 8)); \
	  fi; \
	  if [ "$$ret" = 0 ] && [ "$(TEST_MIGRATIONS)" = 1 ]; then \
	    make test_migrations || ((ret += 16)); \
	  fi; \
	  exit $$ret

test_migrations: PYTEST_ARGS=velodrome/lock8/tests/test_migrations.py
test_migrations:
	$(PYTEST) --create-db --migrations --run-migration-tests

check_migrated: DJANGO_CONFIGURATION:=Tester
check_migrated:
	# Check that there are no DB changes / missing migrations.
	@# "makemigrations --dry-run" exits with 1 if there are no changes.
	@# --noinput works with 1.9+ only (https://code.djangoproject.com/ticket/23407).
	@new_migrations="$$($(MANAGE_PY) makemigrations --check -v3 --dry-run --noinput $(MAIN_APP))"; \
	ret=$$?; \
	if [ $$ret != 0 ]; then \
	  echo 'There are database changes, which should be added to a migration!'; \
	  echo "DJANGO_CONFIGURATION=$$DJANGO_CONFIGURATION."; \
	  echo "ret=$$ret"; \
	  echo '=== new migrations (stdout): ====================='; \
	  echo "$$new_migrations"; \
	  echo '=================================================='; \
	  exit 1; \
	fi;

migrations: DJANGO_CONFIGURATION:=Tester
migrations:
	$(MANAGE_PY) makemigrations $(MAIN_APP)

check: check_django check_flake8 check_pycompile

check_django:
	check_output="$$($(MANAGE_PY) check 2>&1)"; \
	errors="$$(echo "$$check_output" | grep -vE '^(System check identified no issues|INFO:|$$)')"; \
	if [ -n "$$errors" ]; then \
	  echo "There were errors/warnings from Django's 'check' command:"; \
	  echo "$$check_output"; \
	  exit 1; \
	fi

check_flake8:
	flake8 velodrome
check_pycompile:
	output="$$(find velodrome -type f -name '*.py' -print0 \
	    | xargs -0 python -m py_compile 2>&1)"; \
	  if [ -n "$$output" ]; then \
	    echo "There have been errors/warnings when compiling .py files:"; \
	    echo "$$output"; \
	    exit 1; \
	  fi
	
check_isort:
	isort -sp ./setup.cfg --check-only --diff --recursive --skip-glob 'migrations' velodrome

fix_isort:
	isort -sp ./setup.cfg -rc velodrome

check_trackings_integration:
	env DATABASE_URL=$(DB_TESTING) \
		DATABASE_TRACKINGS_URL=$(DB_TRACKINGS_TESTING) \
		$(MANAGE_PY) compare_trackings 100

PROJECT_ROOT:=.
# Define different requirements files.
PIP_REQUIREMENTS_DIR=$(PROJECT_ROOT)/requirements
PIP_REQUIREMENTS_BASE:=$(PIP_REQUIREMENTS_DIR)/base.txt
PIP_REQUIREMENTS_DEV:=$(PIP_REQUIREMENTS_DIR)/dev.txt
PIP_REQUIREMENTS_TRAVIS:=$(PIP_REQUIREMENTS_DIR)/travis.txt
PIP_REQUIREMENTS_PRODUCTION:=$(PIP_REQUIREMENTS_DIR)/production.txt
PIP_REQUIREMENTS_QA:=$(PIP_REQUIREMENTS_DIR)/qa.txt

# Inner-dependencies / includes.
$(PIP_REQUIREMENTS_TRAVIS):: $(PIP_REQUIREMENTS_BASE)
$(PIP_REQUIREMENTS_DEV):: $(PIP_REQUIREMENTS_TRAVIS)
$(PIP_REQUIREMENTS_PRODUCTION):: $(PIP_REQUIREMENTS_BASE)

PIP_REQUIREMENTS_ALL:=$(patsubst %.in,%.txt,$(wildcard $(PIP_REQUIREMENTS_DIR)/*.in))
requirements: $(PIP_REQUIREMENTS_ALL)
requirements_rebuild:
	$(RM) $(PIP_REQUIREMENTS_ALL)
	$(MAKE) requirements PIP_COMPILE_ARGS=--rebuild
bump_requirements:
	git diff --cached --exit-code >/dev/null || { echo "Index is not clean."; exit 1 ; }
	git diff --exit-code requirements/*.txt >/dev/null || { echo 'requirements/*.txt is not clean.'; exit 2 ; }
	$(MAKE) requirements_rebuild
	git checkout -B bump-requirements origin/master
	git add -p requirements
	git commit -m 'Bump requirements'

# Compile/build requirements.txt files from .in files, using pip-compile.
$(PIP_REQUIREMENTS_ALL): PIP_COMPILE_ARGS?=
$(PIP_REQUIREMENTS_ALL):: $(PIP_REQUIREMENTS_DIR)/%.txt: $(PIP_REQUIREMENTS_DIR)/%.in
	@pip-compile --no-header --generate-hashes $(PIP_COMPILE_ARGS) --output-file "$@.tmp" "$<" >"$@.out" || { \
	  ret=$$?; echo "pip-compile failed:" >&2; cat "$@.out" >&2; \
	  $(RM) "$@.tmp" "$@.out"; \
	  exit $$ret; }
	@sed -n '1,10 s/# Depends on/-r/; s/\.in/.txt/p' "$<" > "$@"
	@# Keep and transform '-e git+' as-is (includes the hash).
	@sed -n -e '/-e git+/ {s~^-e git+\(http.*\)@\([^#]\+\)\(#.*\)\?~\1/archive/\2.tar.gz\3~; s~\.git/archive~/archive~; p;}' "$<" >> "$@"
	@# Remove any editables (not supported with hashes).
	@sed -e '/^-e /d' "$@.tmp" >> "$@"
	@$(RM) "$@.tmp" "$@.out"

.PHONY: requirements requirements_rebuild


runserver:
	$(MANAGE_RUNSERVER)

runserver_no_debug:
	DJANGO_DEBUG=False $(MANAGE_RUNSERVER)

shell:
	$(MANAGE_SHELL)

# Run a Django shell and rollback any DB changes.
# This uses https://github.com/fastmonkeys/stellar.
tmpshell: SNAPSHOT_NAME=tmpshell
tmpshell:
	stellar snapshot $(SNAPSHOT_NAME) || stellar replace $(SNAPSHOT_NAME)
	$(MANAGE_SHELL); ret=$$?; \
	  stellar restore $(SNAPSHOT_NAME); \
	  stellar remove $(SNAPSHOT_NAME); \
	  exit $$ret

SSH_HOP_HOST=saltmaster.lock8.me
SSH_TUNNEL_CHECK_COMMAND=nc -z localhost
# Create a SSH tunnel to $2, forwarding the local port $1 to $3.
define func-ssh-tunnel
  @pidfile=$(CURDIR)/build/autossh_$(1).pid; \
  if [ -f "$$pidfile" ]; then \
    echo "Using SSH tunnel to $(2):$(3) on local port $(1)"; \
  else \
    printf "Creating SSH tunnel to $(2):$(3) on local port $(1).."; \
    AUTOSSH_PIDFILE=$$pidfile autossh -f -M 0 -N -L $(1):$(2):$(3) \
    -o ServerAliveInterval=45 -o ServerAliveCountMax=2 $(SSH_HOP_HOST); \
    while ! $(SSH_TUNNEL_CHECK_COMMAND) $(1) >/dev/null 2>&1; do \
      printf '.'; sleep 0.2; \
    done; echo; \
  fi
endef

clean-autossh:
	@shopt -s nullglob; for pidfile in build/autossh_*.pid; do \
	  pid=$$(<$$pidfile); \
	  if ! kill -0 $$pid; then \
	    echo "Removing stale pid file: $$pidfile"; \
	    $(RM) $$pidfile; \
	    continue; \
	  fi; \
	  echo "Killing $$pid ($$pidfile).."; \
	  kill $$pid; \
	done

# Replace database host and port in $(1) with localhost:$(2).
# 1: remote database URL
# 2: local port
define func-substitute-pg-host
$(word 1,$(subst @, ,$(1)))@localhost:$(2)/$(lastword $(subst /, ,$(1)))
endef
define func-dburl-for-env
$(call func-substitute-pg-host,$(if \
	$(DB_$(2)$(call uppercase,$(1))),$(DB_$(2)$(call uppercase,$(1))),$(error Missing host mapping for $(2)$(1))),$(if \
	$(DB_$(2)LOCAL_PORT_$(call uppercase,$(1))),$(DB_$(2)LOCAL_PORT_$(call uppercase,$(1))),$(error Missing port mapping for $(2)$(1))))
endef

# Get PostgreSQL host from database URL (1).
# This splits on "@", then "/" and ":" in the end.
define func-pg-host
$(word 1,$(subst :, ,$(word 1,$(subst /, ,$(word 2,$(subst @, ,$(1)))))))
endef

DB_LOCAL_PORT_TESTING:=65432
DB_LOCAL_PORT_PROD_READONLY:=65433
DB_LOCAL_PORT_PROD:=65434
DB_TRACKINGS_LOCAL_PORT_TESTING:=65435
DB_TRACKINGS_LOCAL_PORT_PROD:=65436
DB_TRACKINGS_LOCAL_PORT_PROD_READONLY:=65437

RUNSERVER_LOCAL_PORT_TESTING:=8001
RUNSERVER_LOCAL_PORT_PROD_READONLY:=8002
RUNSERVER_LOCAL_PORT_PROD:=8003

define uppercase
$(shell echo $(1) | tr a-z A-Z | tr '-' '_')
endef

define func-ssh-tunnel-pg
$(call func-ssh-tunnel,$(DB_LOCAL_PORT_$(1)),$(call func-pg-host,$(DB_$(1))),5432)
endef

define func-ssh-tunnel-pg-trackings
$(call func-ssh-tunnel,$(DB_TRACKINGS_LOCAL_PORT_$(1)),$(call func-pg-host,$(DB_TRACKINGS_$(1))),5432)
endef

ssh-tunnel-pg-testing ssh-tunnel-pg-prod ssh-tunnel-pg-prod-readonly:
	$(call func-ssh-tunnel-pg,$(call uppercase,$(subst ssh-tunnel-pg-,,$@)))

ssh-tunnel-pg-trackings-testing ssh-tunnel-pg-trackings-prod ssh-tunnel-pg-trackings-prod-readonly:
	$(call func-ssh-tunnel-pg-trackings,$(call uppercase,$(subst ssh-tunnel-pg-trackings-,,$@)))

# Run COMMAND with DATABASE_URL substituted for SSH tunnel.
_run_with_local_dburl: export DATABASE_URL=$(call func-dburl-for-env,$(ENV))
_run_with_local_dburl: export DATABASE_TRACKINGS_URL=$(call func-dburl-for-env,$(ENV),TRACKINGS_)
_run_with_local_dburl:
	$(MAKE) ssh-tunnel-pg-$(ENV)
	$(MAKE) ssh-tunnel-pg-trackings-$(ENV)
	$(COMMAND)

runserver-%: ENV=$(subst runserver-,,$@)
runserver-%: RUNSERVER_PORT=$(RUNSERVER_LOCAL_PORT_$(call uppercase,$(ENV)))
runserver-prod-readonly: export DJANGO_CONFIGURATION:=DevProdReadonly
runserver-testing runserver-prod runserver-prod-readonly:
	$(MAKE) _run_with_local_dburl ENV=$(ENV) COMMAND="$(MANAGE_RUNSERVER)"

shell-prod-readonly: export DJANGO_CONFIGURATION:=DevProdReadonly
shell-testing shell-prod shell-prod-readonly:
	$(MAKE) _run_with_local_dburl ENV=$(subst shell-,,$@) COMMAND="$(MANAGE_SHELL)"

manage-prod-readonly: export DJANGO_CONFIGURATION:=DevProdReadonly
manage-testing manage-prod manage-prod-readonly:
	$(MAKE) _run_with_local_dburl ENV=$(subst manage-,,$@) COMMAND="$(MANAGE_PY) $(ARGS)"

runserver-public-%: RUNSERVER_ARGS:=0.0.0.0:9000 -v3 --noreload
runserver-public-%: runserver-% ;

# Update dev environment.
update: build/stamp.install_dev_requirements build/stamp.migrate
.PHONY: update

install_dev_requirements:
	pip install -r $(PIP_REQUIREMENTS_DEV)
.PHONY: install_dev_requirements

migrate:
	$(MANAGE_PY) migrate
.PHONY: migrate

build/stamp.migrate: | build
	@checksum=$$(md5sum velodrome/lock8/migrations/*.py | md5sum); \
	if [ "$$checksum" != "$$(cat "$@" 2>/dev/null)" ]; then \
	  $(MAKE) migrate; \
	  echo "$$checksum" > "$@"; \
	fi
.PHONY: build/stamp.migrate
build/stamp.install_dev_requirements: | build
	@if [ "$(PIP_REQUIREMENTS_DEV)" -nt "$@" ]; then \
	  $(MAKE) install_dev_requirements; \
	  touch "$@"; \
	fi
.PHONY: build/stamp.install_dev_requirements

build:
	mkdir -p build

# Visualize the database with pygraphviz
build-graph: build/wiki/rsc/graph.png
build/wiki/rsc/graph.png: velodrome/lock8/models.py | build/wiki
	$(MANAGE_PY) graph_models $(MAIN_APP) -g -E --pygraphviz -o $@
.PHONY: build-graph

build/wiki:
	if [ -n "$$GH_TOKEN" ]; then \
	  git clone https://$$GH_TOKEN@github.com/lock8/velodrome.wiki.git $@; \
	else \
	  git clone git@github.com:lock8/velodrome.wiki.git $@; \
	fi

docs_remote_update: export GIT_AUTHOR_NAME=lock8-github on Travis CI
docs_remote_update: export GIT_AUTHOR_EMAIL=lock8-github@users.noreply.github.com
docs_remote_update: export GIT_COMMITTER_NAME=$(GIT_AUTHOR_NAME)
docs_remote_update: export GIT_COMMITTER_EMAIL=$(GIT_AUTHOR_EMAIL)
docs_remote_update: build/wiki/rsc/graph.png
	cd build/wiki/ \
	  && git add rsc/graph.png \
	  && git commit -m "updated DB graph" && git push origin master


# Docker {{{
# Indirection for timestamps of requirements files, without triggering a
# rebuild from the .in files.
build/stamp.requirements.%.txt: FORCE
	@touch --reference requirements/$*.txt $@
.PHONY: FORCE

# Base image.
build/stamp.Dockerfile: Dockerfile | build
build/stamp.Dockerfile: build/stamp.requirements.base.txt
build/stamp.Dockerfile: build/stamp.requirements.production.txt
build/stamp.Dockerfile:
	docker build -t velodrome-test-base .
	touch "$@"

# Image for tests (from travis.txt).
build/stamp.Dockerfile.test: build/stamp.Dockerfile etc/Dockerfile.test
build/stamp.Dockerfile.test: build/stamp.requirements.travis.txt
build/stamp.Dockerfile.test:
	docker build -f etc/Dockerfile.test -t velodrome-test-runner .
	touch "$@"

# Image for dev (from dev.txt).
build/stamp.Dockerfile.dev: build/stamp.Dockerfile.test etc/Dockerfile.dev
build/stamp.Dockerfile.dev: build/stamp.requirements.dev.txt
build/stamp.Dockerfile.dev:
	docker build -f etc/Dockerfile.dev -t velodrome-dev-runner .
	touch "$@"

build/envfile.%: %/* %/
	@echo "Generating envfile $@"
	@for i in $^; do \
	  test -f "$$i" || continue; \
	  name=$$(basename $$i); \
	  echo "$$name=$$(cat $$i)" >> $@; \
	done > "$@"

# ENVDIRS can be a list of directories to use, e.g. "envdir envdir.AWS-test".
ENVDIRS?=$(wildcard envdir)
_ENVFILES:=$(foreach envdir,$(ENVDIRS),build/envfile.$(envdir))

DOCKER_VOLUME_SRC:=-v $(CURDIR):/srv/velodrome/src
_docker_run: $(_ENVFILES)
	docker run --net=host $(foreach envfile,$(_ENVFILES),--env-file=$(envfile)) --rm -ti $(DOCKER_VOLUME_SRC) $(DOCKER_ARGS) $(DOCKER_IMAGE) $(DOCKER_RUN_CMD)

docker_sh: build/stamp.Dockerfile.test
docker_sh: DOCKER_IMAGE:=velodrome-test-base
docker_sh: DOCKER_RUN_CMD:=sh
docker_sh: _docker_run

docker_test_integration: build/stamp.Dockerfile build/envfile.envdir.travis
docker_test_integration:
	make _docker_run DOCKER_IMAGE=velodrome-test-base DOCKER_RUN_CMD="\
	  python velodrome/lock8/integration-tests/test-docker.py"
	# Test bin/runvelodrome.sh
	set -ex; \
	  dockertmp=$$(mktemp -d); \
	  dockerid=$$(docker run -d -v $$dockertmp:/tmp \
	    --env-file build/envfile.envdir.travis \
	    -e DJANGO_STATIC_ROOT=/srv/velodrome/static \
	    velodrome-test-base bin/runvelodrome.sh); \
	  docker top $$dockerid; \
	  docker inspect -f {{.State.Running}} $$dockerid; \
	  wait=5; \
	  while ! docker logs $$dockerid 2>&1 | grep -q "spawned uWSGI master process"; do \
	    sleep 1; \
	    if ! ((--wait)); then \
	      echo "master process was not spawned" >&2; \
	      echo "=== docker log: ===" >&2; \
	      docker logs $$dockerid; \
	      exit 1; \
	    fi; \
	  done; \
	  echo q | sudo tee -a $$dockertmp/fifo0; \
	  wait=5; \
	  while $$(docker inspect -f {{.State.Running}} $$dockerid) != false; do \
	    sleep .5; \
	    if ! ((--wait)); then \
	      echo "Docker container was not stopped."; \
	      exit 1; \
	    fi; \
	  done; \
	  if ! docker logs $$dockerid 2>&1 | grep -q "goodbye to uWSGI."; then \
	    echo "uWSGI-goodbye not found in docker-log:" >&2; \
	    echo "=== docker log: ===" >&2; \
	    docker logs $$dockerid; \
	    exit 1; \
	  fi

docker_test: build/stamp.Dockerfile.test
docker_test: DOCKER_ARGS+=-e PYTEST_ADDOPTS
docker_test: DOCKER_IMAGE:=velodrome-test-runner
docker_test: DOCKER_RUN_CMD=make test PYTEST_ARGS="$(PYTEST_ARGS)"
docker_test: _docker_run

docker_dev: build/stamp.Dockerfile.dev
docker_dev: DOCKER_IMAGE:=velodrome-dev-runner
docker_dev: _docker_run

docker_runserver: DOCKER_ARGS+=-p $(RUNSERVER_PORT_DOCKER):$(RUNSERVER_PORT)
docker_runserver: RUNSERVER_ARGS:=0.0.0.0:$(RUNSERVER_PORT)
docker_runserver: DOCKER_RUN_CMD:=make runserver RUNSERVER_ARGS=$(RUNSERVER_ARGS)
docker_runserver: docker_dev
# }}}

# vim: ts=2
