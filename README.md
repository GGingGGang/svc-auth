> 이 애플리케이션 레포지토리는 AI 코드 에이전트가 구현했습니다.

# svc-auth

MSA 인증 서비스 — 사용자 등록 / 로그인 / 세션 / 토큰 발급. Node.js 22 / TypeScript / Fastify 5.
k8s 매니페스트는 [k8s-gitops](https://github.com/GGingGGang/k8s-gitops) 레포의 `manifests/auth/` 소유 (본 레포는 코드 + Dockerfile + Jenkinsfile).

## Ports

| Port | Purpose |
|------|---------|
| `3000` | HTTP API + `/metrics` (single port) |

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe → `{"status":"ok"}` |
| GET | `/readyz` | Readiness probe → `{"status":"ready"}` |
| GET | `/metrics` | Prometheus 스크랩 엔드포인트 |
| POST | `/register` | `{email, password, display_name, timezone}` → 사용자 생성 (argon2id 해싱). 이메일 중복 시 409 |

`/login` `/refresh` `/logout` `/.well-known/jwks.json` 은 추후 추가 예정 (아직 미구현).

## OpenAPI

라우트 스키마(`fastify` `schema` 옵션)에서 `@fastify/swagger` 로 OpenAPI 3.0 스펙을 자동 생성한다. 미구현 엔드포인트는 스펙에 없다 — 실제 등록된 라우트만 나온다.

| Path | 설명 |
|------|------|
| `/documentation` | Swagger UI |
| `/openapi.json` | 원본 OpenAPI 3.0 JSON |

새 라우트를 추가할 때는 `schema.tags` / `schema.summary` / `schema.response`(상태코드별 응답 바디)를 같이 채워야 스펙에 정확히 반영된다. 라우트를 최상위 `app.get/post(...)`로 직접 등록한다면 `app.after(() => { ... })` 안에서 호출할 것 — swagger 플러그인의 `onRoute` 훅이 붙기 전에 동기적으로 라우트가 먼저 등록되면 스펙에서 누락된다 (`src/router.ts` 참고).

## Environment Variables

```bash
HTTP_PORT=3000                    # listen port (default 3000)
DB_HOST=                          # default 127.0.0.1 — 실 배포에서는 반드시 주입
DB_PORT=3306                      # default 3306
DB_USER=                          # default root — 실 배포에서는 반드시 주입
DB_PASSWORD=                      # default empty — never commit
DB_NAME=auth                      # default auth
DB_POOL_SIZE=10                   # default 10 (connection pool)
DB_SSL=true                       # default true (HeatWave requires ssl-mode=REQUIRED); set false for local MySQL
DB_SSL_REJECT_UNAUTHORIZED=false  # default false (HeatWave 서버 인증서에 IP SAN 없음 — 암호화만 수행)
LOG_LEVEL=info                    # default info
APP_VERSION=<GIT_SHA>             # Dockerfile 이 주입 (기본 dev)
```

## Database

```bash
# golang-migrate CLI (db/migrations/0001_init.{up,down}.sql)
migrate -path db/migrations -database "mysql://app_auth:$DB_PASSWORD@tcp($DB_HOST:3306)/auth?tls=true" up
```

## Local Development

```bash
npm ci
docker run -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=auth mysql:8
migrate -path db/migrations -database "mysql://root:root@tcp(localhost:3306)/auth" up
DB_PASSWORD=root DB_SSL=false npm run dev
```

golang-migrate CLI 없이 검증하려면 컨테이너로 대체 가능:

```bash
docker network create svcauth-test-net
docker run -d --name svcauth-mysql --network svcauth-test-net -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=auth -p 3306:3306 mysql:8
docker run --rm --network svcauth-test-net -v "$(pwd)/db/migrations:/migrations" \
  migrate/migrate:v4.18.1 -path=/migrations -database "mysql://root:root@tcp(svcauth-mysql:3306)/auth" up
```

## Build

```bash
npm run build
node dist/server.js
```

## Test

```bash
npm test
```

`vitest` + `testcontainers`(`@testcontainers/mysql`)로 실제 MySQL 컨테이너를 띄워 `0001_init` 마이그레이션 DDL을 적용한 뒤 `/register`를 검증한다 (성공 201, 이메일 중복 409). Docker 데몬이 필요하다.

`/openapi.json` 이 실제 구현된 엔드포인트만 노출하는지(`/documentation`, `/openapi.json` 자체는 스펙에서 숨김)는 `src/router.test.ts` 에서 DB 없이 검증한다.

CI: Jenkins(`services` org folder) → Kaniko → GHCR → Trivy scan(warn) → cosign sign → deployBump → ArgoCD. 배포 시 Kyverno 가 admission 에서 서명 검증(Audit).
