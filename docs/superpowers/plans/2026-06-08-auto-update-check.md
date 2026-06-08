# Auto Update Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build backend automatic update detection and a frontend one-click upgrade entry for SupervisorPanel.

**Architecture:** Add a focused `internal/update` package for version metadata, release checking, cached status, scheduler, and upgrade execution. Wire it into `internal/server` through authenticated APIs and expose status controls in the Vue admin layout.

**Tech Stack:** Go standard library HTTP/exec/sync/time, existing Go `httptest`, Vue 3 + Element Plus + TypeScript.

---

### Task 1: Backend Update Service

**Files:**
- Create: `internal/update/update.go`
- Test: `internal/update/update_test.go`
- Modify: `internal/config/config.go`
- Modify: `cmd/supervisor-panel/main.go`

- [ ] Write failing tests for semantic tag comparison, release JSON parsing, disabled checks, available update detection, and duplicate upgrade protection.
- [ ] Run `go test ./internal/update` and verify the new tests fail because the package does not exist.
- [ ] Implement the minimal update service, config fields, and version variable to pass the tests.
- [ ] Run `go test ./internal/update` and verify it passes.

### Task 2: Backend API Wiring

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

- [ ] Write failing tests for `GET /api/system/update`, `POST /api/system/update/check`, and `POST /api/system/update/upgrade`.
- [ ] Run `go test ./internal/server` and verify the tests fail for missing handlers.
- [ ] Add update service dependency, routes, handlers, and background start method.
- [ ] Run `go test ./internal/server` and verify it passes.

### Task 3: Frontend Update Controls

**Files:**
- Modify: `web/src/types/api.ts`
- Modify: `web/src/api/system.ts`
- Modify: `web/src/layouts/AdminLayout.vue`

- [ ] Add TypeScript API types and client functions.
- [ ] Add a compact update status button in the admin header with check and upgrade actions.
- [ ] Run `npm run build` in `web` and fix any type/build errors.

### Task 4: Full Verification

**Files:**
- No new files.

- [ ] Run `go test ./...`.
- [ ] Run `npm run build` in `web`.
- [ ] Inspect `git diff --stat` and summarize changed files.
