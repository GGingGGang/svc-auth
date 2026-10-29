# svc-auth 구현 기록 (2026-10-28)

## 구현

- `GET /account`, `PATCH /account`를 추가했다. access token 호출자 본인 정보만 다루며, 이름은 앞뒤 공백 제거 후 1~100자, 시간대는 IANA timezone 검증을 적용한다. 알 수 없는 필드는 400으로 거절한다.
- `POST /password/change`를 추가했다. 현재 비밀번호를 다시 확인하고 새 비밀번호 12~128 Unicode code points를 요구한다. 인증 실패 시 변경하지 않고, MySQL row lock transaction에서 Argon2id 해시와 `credential_version`을 함께 갱신한다.
- migration `0003_credential_version`을 추가했다. JWT에는 additive `credential_version` claim을 넣고, 과거 토큰·Redis refresh/session record에 값이 없으면 0으로 처리한다. 로그인은 잠근 user row에서 읽은 버전을 발급에 전달하고, refresh는 DB 버전과 Redis 버전을 대조해 일치할 때만 회전한다. `/introspect`와 auth self-service도 현재 버전을 확인한다.
- 비밀번호 변경은 Redis에서 이전 버전 family만 원자적으로 폐기한다. Redis 장애 시에도 DB 버전 불일치가 이전 access/refresh 토큰을 거절한다. 실패는 민감정보 없이 `session_cleanup_failed`로 기록하며, 뒤늦게 생성된 stale session은 목록에서 정리한다. 동시 비밀번호 변경/로그인 시 새 버전 세션은 폐기하지 않고, 예전 버전 요청에는 노출하지 않는다. 세션 개별 폐기도 소유자와 버전을 Lua 안에서 원자적으로 확인한다.
- 비밀번호 변경 시도에 기존 로그인 제한 설정값을 재사용하는 별도 IP·계정 rate-limit key scope를 추가했다. 로그인 실패 카운터와는 분리했다.

## 검증

- `npx tsc --noEmit` — 통과.
- `npm test` — 9개 파일, 33개 테스트 통과. credential version 전후 access/refresh 차단, Redis 정리 실패 후에도 차단, 로그인/비밀번호 변경 경합에서 오래된 버전 차단, 새 버전 보존, 비밀번호 재인증·정책·rate-limit, 프로필 필드 검증을 확인했다.
- `npm run test:integration` — Docker가 제공되지 않는 환경이라 실행하지 않았다. Testcontainers 기반 실제 MySQL/Redis 시나리오와 migration 적용은 CI에서 확인해야 한다.

## 남은 요구사항

- `ACC-009~013`: 이메일 소유 확인, 단회 링크, 재발송 제한, 확인 후 로그인 흐름, 실제 메일 전송이 없다. 외부 메일 전송 계약·제공자·공개 가입 운영 모드가 정해지지 않아 실제 발송 없이 구현 성공을 가장하지 않았다. `ACC-013`의 공개 가입 출시 게이트도 미완료다.
- `ACN-003~007`: 비밀번호 **변경**에 대한 세션·access 무효화는 구현했다. 이메일 기반 복구 요청/링크/단회 재설정은 이메일 전송 계약이 필요해 미완료다. 따라서 `AC-006` 전체 시나리오도 미완료다.
- `ACN-008`: 이메일 변경과 새 이메일 확인 흐름 미완료(확인 이메일 계약 필요).
- `ACN-009~013`, `AC-022`: 재인증 탈퇴, 여러 서비스의 개인 데이터 정리·재시도·재가입 통제, 백업 보존정책이 필요하다. auth만 수정해 완료 처리할 수 없다.
- `ACN-003`의 Core 요청 차단은 Core가 매 요청 auth `/introspect` 결과를 적용하는 계약 동기화가 전제다. 로컬 Core/전체 배포 경로 검증은 이 작업 범위에서 실행하지 않았다.

## 서비스 계약

root에 다음 additive 계약안을 전달했고 root가 전체 `PLAN.md`의 기록 및 Core/Web 동기화를 담당한다.

- `GET /account` → Bearer 필요, 본인 `{id,email,display_name,timezone}` 반환.
- `PATCH /account` → `{display_name?,timezone?}` 중 하나 이상, 잘못된 값·추가 필드는 400, 성공 시 갱신된 본인 프로필 200.
- `POST /password/change` → Bearer와 `{current_password,new_password}`; 현재 비밀번호 오류 401, 새 비밀번호 정책 위반 400, rate-limit 초과 429 + `Retry-After`, 성공 204.
- JWT의 additive `credential_version`은 기존 누락 토큰을 0으로 읽는다. `/introspect` 응답 모양 `{active:boolean}`은 유지하고 DB 버전을 비교한다. 토큰 claim 형식이 배포 중 함께 맞춰져야 하므로 Core의 introspect 적용을 통합 확인해야 한다.

## 2026-10-29 계정 수명주기 및 운영 기능

### 구현

- 기본 공개가입은 `AUTH_REGISTRATION_MODE`가 비어 있거나 `verified`일 때 이메일 확인을 요구하고, SMTP 설정이 없으면 503으로 실패 종료한다. `demo`는 명시적으로 켠 로컬/내부 모드에서만 이메일 확인을 생략한다. 확인되지 않은 계정은 로그인, introspect, refresh, 프로필, 비밀번호 변경, 세션 API에서 활성 계정으로 인정하지 않는다. 미확인 사용자는 비밀번호와 확인 플래그를 제출하는 전용 탈퇴 경로만 이용할 수 있다.
- `POST /email/verification/request`, `/email/verification/confirm`, `/password/reset/request`, `/password/reset`, `/account/email-change`를 추가했다. 확인 링크는 30분, 재설정 링크는 15분이며 256-bit 난수 토큰의 SHA-256만 저장한다. 토큰은 1회 사용, 재발급 시 같은 목적의 앞선 토큰만 교체한다. 사용자 이메일·토큰 발급과 SMTP outbox 기록은 하나의 MySQL 트랜잭션으로 묶고, outbox 본문은 AES-256-GCM으로 암호화한다. Nodemailer SMTP worker는 재시도하며 PII나 토큰을 로그에 남기지 않는다. 확인 및 재설정 요청은 이메일별 분당 1회/시간당 5회, IP별 시간당 20회로 제한한다.
- 비밀번호/이메일 변경 시 기존 복구 토큰을 무효화하고 `credential_version`을 올려 이전 access/refresh 토큰을 거부한다. 비밀번호 재설정은 토큰 유효성 확인 뒤에만 Argon2를 실행하고, 트랜잭션 안에서 단일 사용 처리·잠금 카운터 초기화·버전 증가를 수행한다. SMTP/외부 이메일은 테스트 중 한 건도 전송하지 않았다.
- JWT에 additive `sid`(refresh family ID)를 넣었다. `GET /sessions`는 `is_current`를 제공하고 `POST /sessions/revoke-others`는 같은 credential version의 다른 세션만 Redis Lua로 폐기한다. `sid`가 없는 구형 토큰은 409 `session_identity_missing`을 반환해 재로그인을 요구한다.
- `DELETE /account`와 미확인 계정용 `POST /account/deletion/unverified`는 재인증, 동의 플래그, 별도 rate limit을 요구한다. 계정은 DB 트랜잭션 안에서 즉시 `deleting`으로 바뀌고 버전 증가, 무작위 receipt hash, 서비스 ACK 상태, durable DB outbox를 함께 기록한다. `app.account.deletion_requested.v1`을 JetStream `ACCOUNT_LIFECYCLE`에 발행하고 `app.account.deletion_result.v1`의 core/batch/notify ACK를 모두 받은 뒤 Redis 세션과 계정을 정리한다. outbox가 결과를 기다리는 동안 주기적으로 재전달하므로 30일 stream 보존기간 뒤에도 재시도가 가능하다. 완료 전까지 이메일은 unique constraint에 남아 재가입을 막는다.
- 내부 계정 상태 조회는 `GET /internal/accounts/:userId/status`에서 `INTERNAL_SERVICE_TOKEN` Bearer를 constant-time 비교하고 `{active,timezone?}`를 반환한다. 운영 정지/해제는 Swagger에서 숨긴 `/internal/accounts/:userId/suspend|unsuspend`에 `OPERATOR_TOKENS_JSON`의 actor->token 맵을 사용한다. actor는 요청 body에서 받지 않는다. 정지는 상태를 잠그고 버전을 증가시키며, 해제는 미확인/삭제/삭제 진행 중 계정을 활성화하지 않는다. 운영 조치는 사유·actor·대상·시각과 함께 감사 테이블에 기록한다.
- `auth_http_requests_total{method,route,status_code}` 및 `auth_http_request_duration_seconds{method,route,status_code}`를 추가했다. route 라벨은 Fastify 경로 템플릿이라 이메일, 사용자 ID, 토큰, raw path는 측정값에 포함되지 않는다.

### API 계약

- 확인/복구 요청은 계정 존재 여부와 무관하게 `202 {accepted:true}`로 응답하며, rate limit은 429, 메일 설정 부재는 503 `email_unavailable`로 실패 종료한다. 확인은 `POST /email/verification/confirm {token}`이며 `{verified:true}` 또는 `{email_changed:true}`를 반환한다. 재설정은 `POST /password/reset {token,new_password}`이며 성공 시 204다.
- 검증된 계정 탈퇴는 `DELETE /account {current_password,confirm:true}` -> `202 {deletion_receipt}`. 미확인 계정은 `POST /account/deletion/unverified {email,password,confirm:true}` -> 일반적으로 202 `{accepted:true}`이며 인증된 요청에만 receipt가 포함된다. 진행 조회는 `GET /account/deletion`에 `X-Deletion-Receipt` 헤더를 전달한다. receipt를 URL query/path에 넣지 않는다.
- 내부 상태 조회 응답은 활성 검증 계정 `{active:true,timezone}`; 미확인/정지/삭제/미존재는 `{active:false}`다. 내부 토큰 설정 누락은 503, 토큰 오류는 401이다.
- 탈퇴 요청 이벤트 payload는 `{event_id,request_id,user_id,credential_version,occurred_at}`이고 이메일 등 계정 PII를 담지 않는다. 서비스별 결과 ACK는 `{event_id,request_id,service,status,occurred_at}`다. stream/durable은 서비스 운영 설정에서 provision해야 한다.

### 검증

- `npm test`: 12개 테스트 파일, 41개 테스트 통과. 암호화 payload tamper 검출, fake SMTP transport에서 fragment 링크 사용, 공개 가입 fail-closed, 내부 bearer/actor 인증, 미확인 탈퇴 확인, reset 토큰 단일 사용/버전 증가, 고정 metric 라벨을 검사했다. 기존 세션 통합 테스트에 sid 기반 현재 세션/기타 세션 폐기와 sid 없는 JWT 거절도 추가했다.
- `npm run build` 및 `npx tsc --noEmit`: 통과.
- Testcontainers 통합 테스트는 이 환경에 Docker daemon이 없어 실행하지 않았다. MySQL migration의 실제 적용/JetStream 서비스 ACK 및 실제 SMTP 전송은 실환경 설정 후 확인해야 한다. 테스트에서는 실제 이메일을 보내지 않았다.

### 남은 외부 운영 확인

- ACC-009~013, LGN-013, SES-011/012, ACN-001~013, OPS-001/006의 서비스 코드·단위 검증을 구현했다. SMTP URL/발신자/32-byte 암호화 키와 `WEB_APP_URL`, `INTERNAL_SERVICE_TOKEN`, `OPERATOR_TOKENS_JSON`, NATS_URL 및 ACCOUNT_LIFECYCLE stream/durable ACL은 운영 배포에서 설정되어야 한다. SMTP/NATS 미설정 상태에서 공개 가입은 실패 종료하고, 탈퇴 outbox는 DB에 보존된다.
- 다른 서비스의 삭제 소비자가 성공 ACK를 내는 것과 운영 ingress가 `/internal/*`를 외부에 노출하지 않는지는 통합 환경에서 확인이 필요하다. 확인되지 않은 백업의 즉시 파기를 주장하지 않는다. ACN-012의 backup retention/compliance 증빙은 운영 정책 소유자 확인이 남아 있다.

### 2026-10-29 삭제 프로토콜 후속 대조

- 현재 auth 발행 이벤트와 소비자 구현을 대조했다. subject는 `app.account.deletion_requested.v1`, 결과는 `app.account.deletion_result.v1`, stream은 `ACCOUNT_LIFECYCLE`이며 공통 payload 필드와 `core`/`batch`/`notify` service 이름이 일치한다. 실제 consumer durable은 core `svc-core-account-deletion`, batch `batch-account-deletions`, notify `notify-account-cleanup`; auth 결과 durable 기본값은 `auth-deletion-results`다. 모든 소비자는 정리 성공 후 `completed` ACK를 내고, 재시도는 처리 실패 시 NAK 또는 core `retry` ACK로 표현한다.
- auth의 DB outbox는 동일 event ID로 재발행하며 완료 ACK를 서비스별 DB 상태에 반영한다. `retry` ACK는 즉시 재발행을 예약한다. 3개 서비스 완료 후 세션 폐기 및 사용자 hard delete를 수행하고 receipt 상태를 `completed`로 바꾼 뒤 outbox를 제거한다. DB/Redis 처리 실패 시 JetStream ACK 전에 NAK되어 재전달된다. receipt 원문은 `X-Deletion-Receipt`로만 받으며 DB에는 해시만 저장한다.
- 대조 중 발견한 결함을 수정했다. auth가 시작될 때 stream/durable 조회에 실패하면 결과 consumer가 영구 종료되던 동작을 supervised retry로 바꿨다. 연결이 닫힌 경우 재연결하고, provisioning 전/일시 장애는 5초 간격으로 다시 조회한다. stream/durable은 계속 외부 운영 설정으로 관리하며 auth가 만들지 않는다. 발행 및 consumer 장애는 payload/URL을 포함하지 않는 코드형 로그를 분당 한 번 남긴다.
- `npm test`: 13개 파일, 43개 테스트 통과(삭제 ACK 계약 검증과 consumer 재획득 회귀 포함). `npm run build`, `npx tsc --noEmit`, `git diff --check` 통과. 실 NATS/DB 종단 간 재전달은 Docker/NATS 환경 부재로 미실행이며 운영 stream ACL, consumer provisioning, ingress 노출 여부 및 backup retention/compliance 확인은 여전히 운영 확인 항목이다. SMTP 및 Telegram 발송 설정은 변경하지 않았고 전송도 하지 않았다.
