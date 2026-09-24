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
| GET | `/sessions` | `Authorization: Bearer <access-token>` 필수 → 호출자의 활성 세션(로그인/기기) 목록 |
| DELETE | `/sessions/{familyId}` | `Authorization: Bearer <access-token>` 필수 → 해당 세션 강제 로그아웃(refresh family 폐기). 소유자 아닌 family_id 는 404 |

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
JWT_SECONDARY_KEY_PEM=             # ES256 PEM — 선택. 키 회전 중에만 설정, JWKS 에 publish 만 되고 서명에는 안 쓰임 ("Key Rotation" 참고)
JWT_ISSUER=auth.ggang.cloud        # access JWT 의 iss claim
ACCESS_TTL=3600                   # access JWT TTL(초)
REFRESH_TTL=1209600               # refresh 토큰 TTL(초, sliding) — 14d
REDIS_ADDR=127.0.0.1:6379          # host:port. 실 배포는 redis.data.svc.cluster.local:6379
REDIS_DB=0                         # refresh token / family / rate-limit 저장 DB index

LOGIN_RATE_LIMIT_IP_MAX=20             # 기본 20 — IP 당 window 내 최대 /login 시도
LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS=60  # 기본 60초
LOGIN_RATE_LIMIT_EMAIL_MAX=10          # 기본 10 — 이메일 당 window 내 최대 /login 시도
LOGIN_RATE_LIMIT_EMAIL_WINDOW_SECONDS=60  # 기본 60초
LOGIN_LOCKOUT_THRESHOLD=5              # 기본 5 — 이 횟수만큼 비밀번호 연속 실패 시 임시 잠금
LOGIN_LOCKOUT_WINDOW_SECONDS=900       # 기본 900초(15분) — 첫 실패부터 집계 기간
LOGIN_LOCKOUT_DURATION_SECONDS=900     # 기본 900초(15분) — 마지막 실패부터 잠금 기간
TRUSTED_PROXY_CIDRS=                  # 쉼표 구분 CIDR; 실제 ingress/proxy 소스만 지정. 미설정 시 전달된 IP 헤더 무시

OTEL_SERVICE_NAME=auth                  # 기본 auth. resource attribute service.name
OTEL_RESOURCE_ATTRIBUTES=              # 예: service.namespace=auth,service.version=<git-sha>
OTEL_TRACES_EXPORTER=none              # 기본 none(no-op) — collector 배포 후 otlp 로 전환
OTEL_EXPORTER_OTLP_ENDPOINT=           # 예: http://alloy.monitoring.svc:4317 (otlp 일 때만 사용)
OTEL_EXPORTER_OTLP_PROTOCOL=grpc       # OTLPTraceExporter(grpc) 고정
```

## Login Security

`POST /login` 은 두 계층의 브루트포스 방어를 갖는다 (`src/loginSecurity.ts`):

- **Rate limit** — Redis DB0 고정 윈도우 카운터. IP 단위(`auth:loginrl:ip:<ip>`)와 이메일 단위(`auth:loginrl:email:<sha256(email)>`, 이메일은 해시 후 저장)를 모두 검사하며 어느 한쪽이라도 초과하면 `429 {"error":"rate_limited"}` + `Retry-After` 헤더를 반환한다. IP 체크가 이메일 체크보다 먼저 실행된다.
- **Account lockout** — 첫 실패부터 `LOGIN_LOCKOUT_WINDOW_SECONDS` 내 비밀번호 오류가 임계치에 도달하면 MySQL `login_locked_until`까지 임시 잠금한다. 잠금 만료 시 자동 해제되며, 운영상 `users.status`는 변경하지 않는다. 로그인 판정·실패 횟수 갱신·성공 시 초기화는 사용자 행 잠금 아래 처리한다. 서비스 시작 시 `0002_login_lockout` 마이그레이션이 자동 적용된다.

두 계층 모두 이메일 존재 여부를 흘리지 않도록 미가입 이메일도 동일하게 카운트된다.

## Key Rotation

`kid` 는 항상 키 자체에서(RFC 7638 JWK thumbprint) 계산되므로 (`src/keys.ts`), 회전은 PEM 을 바꿔치기하는 것만으로 새 `kid` 가 자동으로 따라온다. `POST /login`·`/refresh` 는 항상 `JWT_PRIVATE_KEY_PEM`(활성 서명 키)으로만 서명하고, `GET /.well-known/jwks.json` 은 이 키의 공개키에 더해 `JWT_SECONDARY_KEY_PEM`(설정된 경우)의 공개키도 함께 노출한다 — 이 두 번째 슬롯은 **절대 서명에 쓰이지 않고 JWKS 공개용으로만** 존재한다 (`src/routes/jwks.ts`).

`PLAN.md` §6 이 정의하는 실제 회전 절차 (사람이 두 env 를 어떻게 바꾸는지):

1. **사전 공개** — 새 키 페어를 생성해 그 PEM 을 `JWT_SECONDARY_KEY_PEM` 에 넣고 배포. `JWT_PRIVATE_KEY_PEM` 은 그대로(구 키가 계속 서명). JWKS 는 이제 구/신 키 둘 다 노출 — core 의 JWKS 캐시가 새 `kid` 를 미리 알게 된다. 최소 24h 유지.
2. **전환(cutover)** — `JWT_PRIVATE_KEY_PEM` 을 새 키로, `JWT_SECONDARY_KEY_PEM` 을 구 키로 맞바꿔 배포. 서명은 이제 새 키로 전환되지만, 전환 이전에 발급된 access 토큰(구 키 서명)은 구 키가 여전히 JWKS 의 두 번째 슬롯에 있으므로 core 검증이 끊기지 않는다.
3. **정리** — 구 키로 서명된 토큰의 `ACCESS_TTL` 이 전부 만료된 뒤 `JWT_SECONDARY_KEY_PEM` 을 비우고 재배포. JWKS 는 다시 키 1개로 돌아간다.

이 절차가 실제로 무중단인지는 `src/keyRotation.test.ts` 가 Docker 없이 검증한다 — 두 개의 인메모리 앱 인스턴스로 "전환 전"/"전환 후"를 흉내내고, 전환 전에 구 키로 서명한 토큰이 전환 후 JWKS 로도 여전히 검증되는지 직접 확인한다.

## Session Management

`GET /sessions` / `DELETE /sessions/{familyId}` (`src/routes/sessions.ts`)은 `Authorization: Bearer <access-token>` 로 인증한다 — auth 가 자기 자신이 발급한 access 토큰을 검증하는 유일한 경로(`src/accessAuth.ts`, `jose.jwtVerify` 로 로컬 공개키 검증, core 처럼 JWKS 왕복은 안 함). `aud` 검증은 의도적으로 생략 — `aud=core` 로 발급된 토큰이라도 issuer 인 auth 자신이 자기 토큰을 들여다보는 것이므로 다른 relying party 로의 재생 방지라는 `aud` 의 존재 이유와 무관하다. 키 회전 중에도 끊기지 않도록 `signingKey`뿐 아니라 `secondaryKey`(설정된 경우)로도 검증을 시도한다.

- **세션 = refresh token family**: 로그인마다 새 family 가 시작되므로(`src/tokens.ts` `issueTokenPair`) family 하나가 사실상 기기/로그인 하나. `auth:session:<family_id>`(`{user_id, created_at, last_active_at}`, family 와 동일한 sliding TTL)에 메타데이터를, `auth:userfam:<user_id>`(Set)에 "이 유저의 family 목록" 역인덱스를 함께 유지한다 — refresh 회전마다 `last_active_at` 만 갱신되고 `created_at`(최초 로그인 시각)은 유지된다.
- **GET /sessions**: `auth:userfam:<user_id>` 를 순회해 세션 목록을 반환. 인덱스에는 있지만 세션 키가 이미 만료된 항목은 그 자리에서 제거(self-heal).
- **DELETE /sessions/{familyId}**: `revokeFamily`(기존 `/logout`이 이미 쓰던 함수)를 재사용 — 특정 refresh 토큰 없이도 다른 기기를 지목해 강제 로그아웃할 수 있게 한 것뿐, 폐기 메커니즘 자체는 동일하다. 호출자 소유가 아닌 family_id 는 404(존재 여부 미노출).
- **한계**: `../PLAN.md` §13 정정 #6 이 `/verify` introspection 을 폐기하고 JWKS 전용 로컬 검증으로 확정했기 때문에, 이미 발급된 access 토큰을 이 API 로 **즉시** 무효화할 방법은 없다 — 강제 로그아웃은 이후 refresh 를 막을 뿐이고, 아직 만료 전인 access 토큰은 `ACCESS_TTL` 만큼 그대로 유효하다(문서상 `auth:blk:<jti>` 블랙리스트 키가 언급돼 있었지만 이 아키텍처 결정과 맞지 않아 구현하지 않았다).

`src/accessAuth.test.ts` 가 자체 검증 로직을(주 키/보조 키/서명자 불일치/잘못된 토큰 4케이스) Docker 없이 검증하고, `src/routes/sessions.integration.test.ts` 가 Redis testcontainers 로 목록 스코핑·회전 시 세션 미증식·강제 로그아웃 후 refresh 차단·타인 세션 폐기 시도 404 를 검증한다(MySQL 은 불요 — `issueTokenPair` 를 `/login` 대신 직접 호출해 로그인을 흉내낸다).

## Observability

`src/observability/tracing.ts` 가 `../PLAN.md` §8.2 최소 배선을 구현한다:

- W3C TraceContext + Baggage 전파는 항상 켜져 있다(`CompositePropagator`). 인바운드 `traceparent` 가 있으면 그 trace 를 이어받는다.
- `TracerProvider` 는 항상 실제 span/trace id 를 생성한다 — 로그(`src/observability/httpTracing.ts` 가 매 요청마다 `trace_id`/`span_id` 를 request/reply logger 에 bind, §8.1 JSON 로그 스키마) 는 collector 유무와 무관하게 항상 채워진다.
- 실제 OTLP export(span processor)는 `OTEL_TRACES_EXPORTER=otlp` 일 때만 켜진다 — collector 미배포 상태의 기본값(`none`)에서는 어떤 아웃바운드 연결도 만들지 않는다.
- span attribute 는 `http.request.method` / `http.route` / `http.response.status_code` 뿐 — email/user_id 등 PII 는 절대 포함하지 않는다(§8.1).

## Database

On startup, the service applies pending `db/migrations/*.up.sql` files using the
existing `schema_migrations` table before opening its HTTP port. A failed or
dirty migration stops startup. The runtime image includes these SQL files.

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

`src/keyRotation.test.ts` 는 DB 없이 "Key Rotation" 섹션의 회전 절차를 검증한다 — 회전 전/후를 흉내낸 두 인메모리 앱 인스턴스로 JWKS 가 두 키를 동시에 노출하는지, 회전 전 구 키로 서명한 토큰이 회전 후 JWKS 로도 계속 검증되는지, 보조 키가 없을 때는 JWKS 가 키 1개만 노출하는지를 확인한다.

`src/routes/auth-flow.integration.test.ts` 가 이미 register→login→JWKS 검증→refresh(회전)→refresh 재사용 감지→logout 전체 토큰 플로우를 e2e 로 검증한다 (2M 에 작성, 회귀 스위트로 계속 실행).

`src/routes/register.integration.test.ts` 는 `@testcontainers/mysql` 로 실제 MySQL 컨테이너를 띄워 `0001_init` 마이그레이션 DDL을 적용한 뒤 `/register`를 검증한다 (성공 201, 이메일 중복 409).

`src/routes/auth-flow.integration.test.ts` 는 `@testcontainers/mysql` + `@testcontainers/redis` 로 MySQL/Redis 를 함께 띄워 `register → login → JWKS 검증 → refresh(회전) → refresh 재사용 감지(family 폐기) → logout` 전체 시나리오를 검증한다. JWKS 검증은 `/.well-known/jwks.json` 응답의 공개키를 `jose`(`importJWK`+`jwtVerify`)로 실제 access JWT 서명 검증까지 수행 — core 가 JWKS 로 검증하는 경로를 그대로 재현한다. 서명 키는 매 테스트 실행마다 `jose.generateKeyPair`로 생성한 임시 ES256 키(`src/test-support/signing-key.ts`)를 쓰며 k8s Secret 을 건드리지 않는다.

`src/routes/login-security.integration.test.ts` 는 MySQL+Redis testcontainers 로 로그인 rate limit, 임시 잠금·자동 해제, 동시 실패 집계를 검증한다. 매 테스트 전 `redis.flushdb()` 로 rate-limit 카운터를 초기화한다.

CI: Jenkins(`services` org folder, 유닛 게이트) → Kaniko → GHCR → Trivy scan(warn) → cosign sign → deployBump → ArgoCD (배포 시 Kyverno 가 admission 에서 서명 검증, Audit). 별도로 이 repo의 `.github/workflows/test.yml` (GitHub Actions) 이 push(main)/PR 마다 유닛+통합 풀 스위트를 실행 — Jenkins 파이프라인과 병렬이며 이미지 생성 게이트에는 관여하지 않는다.
