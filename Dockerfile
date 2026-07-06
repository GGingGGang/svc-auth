FROM docker.io/node:22-alpine AS builder
WORKDIR /src
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM gcr.io/distroless/nodejs22-debian12:nonroot
ARG GIT_SHA=unknown
ENV APP_VERSION=${GIT_SHA}
WORKDIR /app
COPY --from=builder /src/node_modules ./node_modules
COPY --from=builder /src/dist ./dist
COPY --from=builder /src/package.json ./
USER nonroot:nonroot
EXPOSE 3000
# distroless nodejs 의 ENTRYPOINT 는 node — CMD 는 스크립트 경로만
CMD ["dist/server.js"]
