BIN := backend/bin/cassandra-apiserver

.PHONY: build web backend cli test release run dev-api dev-web clean

build: web backend

web:
	cd web && npm ci --no-audit --no-fund && npm run build

backend: cli
	cd backend && go build -o bin/cassandra-apiserver ./cmd/cassandra-apiserver

cli:
	cd backend && go build -o bin/cassandra ./cmd/cassandra

test:
	bash -n scripts/release.sh
	python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
	cd backend && go vet ./... && go test -race -timeout 5m ./...
	cd web && npm test && npm run typecheck

# Produces archives and checksums only; never tags, pushes or publishes.
release:
	bash scripts/release.sh "$(VERSION)" dist

# Serves the API and the built UI on http://127.0.0.1:8080.
run: build
	$(BIN) --static-dir web/dist

# Development: API on :8080, Vite with hot reload on :5173 proxying /apis.
dev-api: backend
	$(BIN)

dev-web:
	cd web && npm run dev -- --host 127.0.0.1

clean:
	rm -rf backend/bin web/dist
