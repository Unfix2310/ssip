.PHONY: run test compile up

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

test:
	pytest -q

compile:
	python3 -m compileall app tests scripts

up:
	docker compose up --build
