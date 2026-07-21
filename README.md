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
| POST | `/login` | `{email, password}` → access(JWT ES256, TTL `ACCESS_TTL`) + refresh(opaque, Redis DB0 저장) 발급. 실패 시 401 |
| POST | `/refresh` | `{refresh_token}` → refresh 회전(one-time use, sliding TTL `REFRESH_TTL`) 후 새 access+refresh 쌍 발급. 이미 소비된 토큰 재사용 시 401 + 해당 family 전체 폐기 |
| POST | `/logout` | `{refresh_token}` → 토큰이 속한 family 전체를 Redis 에서 폐기. 알 수 없는 토큰이어도 204 (idempotent) |
| GET | `/.well-known/jwks.json` | ES256 공개키 JWK set. `Cache-Control: max-age=3600`. `kid` 는 키의 RFC 7638 JWK thumbprint |

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
JWT_PRIVATE_KEY_PEM=               # ES256 PEM 개인키 — 필수, never commit. 없으면 서버가 기동 실패
JWT_ISSUER=auth.ggang.cloud        # access JWT 의 iss claim
ACCESS_TTL=3600                   # access JWT TTL(초)
REFRESH_TTL=1209600               # refresh 토큰 TTL(초, sliding) — 14d
REDIS_ADDR=127.0.0.1:6379          # host:port. 실 배포는 redis.data.svc.cluster.local:6379
REDIS_DB=0                         # refresh token / family 저장 DB index
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
docker run -d -p 6379:6379 redis:7
migrate -path db/migrations -database "mysql://root:root@tcp(localhost:3306)/auth" up
DB_PASSWORD=root DB_SSL=false JWT_PRIVATE_KEY_PEM="$(openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt)" npm run dev
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

`src/routes/auth-flow.test.ts` 는 `@testcontainers/mysql` + `@testcontainers/redis` 로 MySQL/Redis 를 함께 띄워 `register → login → JWKS 검증 → refresh(회전) → refresh 재사용 감지(family 폐기) → logout` 전체 시나리오를 검증한다. JWKS 검증은 `/.well-known/jwks.json` 응답의 공개키를 `jose`(`importJWK`+`jwtVerify`)로 실제 access JWT 서명 검증까지 수행 — core 가 JWKS 로 검증하는 경로를 그대로 재현한다. 서명 키는 매 테스트 실행마다 `jose.generateKeyPair`로 생성한 임시 ES256 키(`src/test-support/signing-key.ts`)를 쓰며 k8s Secret 을 건드리지 않는다.

`/openapi.json` 이 실제 구현된 엔드포인트만 노출하는지(`/documentation`, `/openapi.json` 자체는 스펙에서 숨김)는 `src/router.test.ts` 에서 DB 없이 검증한다.

CI: Jenkins(`services` org folder) → Kaniko → GHCR → Trivy scan(warn) → cosign sign → deployBump → ArgoCD. 배포 시 Kyverno 가 admission 에서 서명 검증(Audit).
