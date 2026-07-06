// hello 서버까지 — 도메인 라우트(사용자/인증/세션/토큰)는 생성된 서비스가 직접 추가.

export async function healthz() {
  return { status: "ok" };
}

export async function readyz() {
  return { status: "ready" };
}
