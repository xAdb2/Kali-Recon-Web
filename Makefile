# KaliRecon Web — developer & operator commands
COMPOSE ?= docker compose
PREBUILT = -f compose.yml -f compose.prebuilt.yml

.PHONY: help install build pull up down restart logs migrate createsuperuser \
        test lint smoke clean-orphans config collectstatic shell

help:
	@echo "make install         # run scripts/install.sh"
	@echo "make build           # build app + scanner images locally"
	@echo "make pull            # pull prebuilt GHCR images"
	@echo "make up / down       # start / stop the stack"
	@echo "make restart logs    # restart / follow logs"
	@echo "make migrate         # apply migrations"
	@echo "make createsuperuser # create admin (create_admin command)"
	@echo "make test lint smoke # run tests / ruff / smoke test"
	@echo "make clean-orphans   # remove orphaned scanner containers"

install:
	./scripts/install.sh

build:
	$(COMPOSE) build
	$(COMPOSE) --profile scanner build scanner-build || \
	  docker build -t $${SCANNER_IMAGE:-kalirecon-scanner:local} -f docker/scanner.Dockerfile .

pull:
	$(COMPOSE) $(PREBUILT) pull

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart

logs:
	$(COMPOSE) logs -f --tail=200

migrate:
	$(COMPOSE) exec web python manage.py migrate

collectstatic:
	$(COMPOSE) exec web python manage.py collectstatic --noinput

createsuperuser:
	$(COMPOSE) exec web python manage.py create_admin

shell:
	$(COMPOSE) exec web python manage.py shell

config:
	$(COMPOSE) config

test:
	python -m pytest -q

lint:
	python -m ruff check .

smoke:
	./scripts/smoke-test.sh

clean-orphans:
	$(COMPOSE) exec worker python manage.py cleanup_orphan_scanners
