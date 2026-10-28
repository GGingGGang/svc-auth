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
