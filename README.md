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
| POST | `/login` | `{email, password}` → access(JWT ES256, TTL `ACCESS_TTL`) + refresh(opaque, Redis DB0 저장) 발급. 자격증명 실패 401(`invalid_credentials`), 계정 잠김 401(`account_locked`), IP/이메일 rate limit 초과 429(`rate_limited`, `Retry-After` 헤더) |
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
REDIS_DB=0                         # refresh token / family / rate-limit / lockout counter 저장 DB index

LOGIN_RATE_LIMIT_IP_MAX=20             # 기본 20 — IP 당 window 내 최대 /login 시도
LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS=60  # 기본 60초
LOGIN_RATE_LIMIT_EMAIL_MAX=10          # 기본 10 — 이메일 당 window 내 최대 /login 시도
LOGIN_RATE_LIMIT_EMAIL_WINDOW_SECONDS=60  # 기본 60초
LOGIN_LOCKOUT_THRESHOLD=5              # 기본 5 — 이 횟수만큼 비밀번호 연속 실패 시 users.status='locked'
LOGIN_LOCKOUT_WINDOW_SECONDS=900       # 기본 900초(15분) — 실패 카운터 TTL(성공 로그인 시 즉시 리셋)

OTEL_SERVICE_NAME=auth                  # 기본 auth. resource attribute service.name
OTEL_RESOURCE_ATTRIBUTES=              # 예: service.namespace=auth,service.version=<git-sha>
OTEL_TRACES_EXPORTER=none              # 기본 none(no-op) — collector 배포 후 otlp 로 전환
OTEL_EXPORTER_OTLP_ENDPOINT=           # 예: http://alloy.monitoring.svc:4317 (otlp 일 때만 사용)
OTEL_EXPORTER_OTLP_PROTOCOL=grpc       # OTLPTraceExporter(grpc) 고정
```

## Login Security

`POST /login` 은 두 계층의 브루트포스 방어를 갖는다 (`src/loginSecurity.ts`):

- **Rate limit** — Redis DB0 고정 윈도우 카운터. IP 단위(`auth:loginrl:ip:<ip>`)와 이메일 단위(`auth:loginrl:email:<sha256(email)>`, 이메일은 해시 후 저장)를 모두 검사하며 어느 한쪽이라도 초과하면 `429 {"error":"rate_limited"}` + `Retry-After` 헤더를 반환한다. IP 체크가 이메일 체크보다 먼저 실행된다.
- **Account lockout** — 비밀번호 불일치가 `LOGIN_LOCKOUT_THRESHOLD` 회 누적되면(`auth:loginfail:<user_id>`, TTL `LOGIN_LOCKOUT_WINDOW_SECONDS`) `users.status` 를 `active` → `locked` 로 전환(`PLAN.md` §6.3 ENUM)하고 Redis 카운터를 정리한다. 이미 잠긴 계정은 비밀번호가 맞아도 `401 {"error":"account_locked"}`. 로그인 성공 시 실패 카운터는 즉시 리셋된다.

두 계층 모두 이메일 존재 여부를 흘리지 않도록 미가입 이메일도 동일하게 카운트된다.

## Observability

`src/observability/tracing.ts` 가 `../PLAN.md` §8.2 최소 배선을 구현한다:

- W3C TraceContext + Baggage 전파는 항상 켜져 있다(`CompositePropagator`). 인바운드 `traceparent` 가 있으면 그 trace 를 이어받는다.
- `TracerProvider` 는 항상 실제 span/trace id 를 생성한다 — 로그(`src/observability/httpTracing.ts` 가 매 요청마다 `trace_id`/`span_id` 를 request/reply logger 에 bind, §8.1 JSON 로그 스키마) 는 collector 유무와 무관하게 항상 채워진다.
- 실제 OTLP export(span processor)는 `OTEL_TRACES_EXPORTER=otlp` 일 때만 켜진다 — collector 미배포 상태의 기본값(`none`)에서는 어떤 아웃바운드 연결도 만들지 않는다.
- span attribute 는 `http.request.method` / `http.route` / `http.response.status_code` 뿐 — email/user_id 등 PII 는 절대 포함하지 않는다(§8.1).

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

유닛(Docker 불요)과 통합(testcontainers, Docker 필요)이 분리되어 있다 (`../test-contract.md` §3). 통합 테스트는 파일명 `*.integration.test.ts` 컨벤션으로 `vitest.config.ts` 기본 설정에서 제외된다.

```bash
npm test                  # 유닛만 (vitest.config.ts). Docker 불요 — Jenkins 유닛 게이트가 실행
npm run test:integration  # 통합만 (vitest.integration.config.ts). Docker 데몬 필요 — 이 repo의 GitHub Actions 가 실행
```

`src/router.test.ts` 는 `/openapi.json` 이 실제 구현된 엔드포인트만 노출하는지(`/documentation`, `/openapi.json` 자체는 스펙에서 숨김)를 DB 없이 검증한다.

`src/observability/httpTracing.test.ts` 는 DB 없이 순수 Fastify 인스턴스로 W3C `traceparent` 헤더 전파(인바운드 trace id 를 그대로 이어받는지), 헤더가 없을 때 유효한 trace id 를 새로 발급하는지, span/로그에 PII 가 들어가지 않는지를 검증한다.

`src/routes/register.integration.test.ts` 는 `@testcontainers/mysql` 로 실제 MySQL 컨테이너를 띄워 `0001_init` 마이그레이션 DDL을 적용한 뒤 `/register`를 검증한다 (성공 201, 이메일 중복 409).

`src/routes/auth-flow.integration.test.ts` 는 `@testcontainers/mysql` + `@testcontainers/redis` 로 MySQL/Redis 를 함께 띄워 `register → login → JWKS 검증 → refresh(회전) → refresh 재사용 감지(family 폐기) → logout` 전체 시나리오를 검증한다. JWKS 검증은 `/.well-known/jwks.json` 응답의 공개키를 `jose`(`importJWK`+`jwtVerify`)로 실제 access JWT 서명 검증까지 수행 — core 가 JWKS 로 검증하는 경로를 그대로 재현한다. 서명 키는 매 테스트 실행마다 `jose.generateKeyPair`로 생성한 임시 ES256 키(`src/test-support/signing-key.ts`)를 쓰며 k8s Secret 을 건드리지 않는다.

`src/routes/login-security.integration.test.ts` 는 MySQL+Redis testcontainers 로 로그인 rate limit(이메일/IP 각각 초과 시 429 + `Retry-After`)과 계정 잠금(연속 실패 임계치 도달 시 `users.status='locked'` 전환 + 이후 정상 비밀번호도 거부, 로그인 성공 시 실패 카운터 리셋)을 검증한다. 매 테스트 전 `redis.flushdb()` 로 카운터를 초기화해 테스트 간 간섭을 없앤다.

CI: Jenkins(`services` org folder, 유닛 게이트) → Kaniko → GHCR → Trivy scan(warn) → cosign sign → deployBump → ArgoCD (배포 시 Kyverno 가 admission 에서 서명 검증, Audit). 별도로 이 repo의 `.github/workflows/test.yml` (GitHub Actions) 이 push(main)/PR 마다 유닛+통합 풀 스위트를 실행 — Jenkins 파이프라인과 병렬이며 이미지 생성 게이트에는 관여하지 않는다.
