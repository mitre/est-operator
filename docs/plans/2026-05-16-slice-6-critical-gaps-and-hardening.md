# Slice 6: Critical Gaps & Hardening

## P0 — Security & Correctness

### Task 1: Wire CAcert to EST client for TLS verification
**Problem:** `EstIssuer.Spec.CAcert` and `EstClusterIssuer.Spec.CAcert` are defined in the API but never passed to `estclient.Config.CACerts`. Without it, the EST client uses default system CAs and cannot verify the portal's identity — this is a security defect.

**Files:**
- Modify: `internal/controller/estorder_controller.go` — `resolveIssuerConfig` and `resolveIssuerWithCredentials` must decode the `CAcert` base64 PEM field and include it in the `estclient.Config`
- Modify: `internal/controller/estissuer_controller.go` — `checkIssuerConnectivity` should use `CAcert` for TLS verification
- Test: `internal/controller/slice4_test.go` — add test that CAcert is populated in Config

**Implementation:**
```go
// In resolveIssuerConfig / resolveIssuerWithCredentials:
decoded, err := base64.StdEncoding.DecodeString(issuer.Spec.CAcert)
cfg.CACerts = decoded
```

**TDD:**
1. Write test: `TestResolveIssuerWithCredentials_IncludesCACert` — verify the returned `estclient.Config` has `CACerts` populated from the issuer's `CAcert` field
2. Write test: `TestResolveIssuerConfig_IncludesCACert` — same for host-only resolution

---

### Task 2: Regenerate RBAC manifests
**Problem:** RBAC markers were added to controller files but `make manifests` must be re-run to update `config/rbac/role.yaml` and CRDs with the new secret access and cert-manager permissions.

**Steps:**
1. Run `make manifests`
2. Verify `config/rbac/role.yaml` contains `secrets    [get,list,watch]` and cert-manager CertificateRequest permissions
3. Verify CRDs include `rootPin` on `EstClusterIssuer`

**Effort:** 5 minutes

---

## P1 — Feature Completeness

### Task 3: Use Label field in URL construction
**Problem:** RFC 7030 §3.2.2 specifies that the EST portal path includes an optional label. `EstIssuer.Spec.Label` and `EstClusterIssuer.Spec.Label` exist in the API but `estclient.Config` and `buildURL()` don't use them.

**Files:**
- Modify: `internal/estclient/client.go` — add `Label string` to `Config`, incorporate into `buildURL()`
- Modify: `internal/controller/estorder_controller.go` — pass `Label` from issuer spec to `estclient.Config`
- Test: `internal/estclient/client_test.go` — add `TestBuildURL_WithLabel`

**Implementation:**
```go
// In Config:
Label string

// In buildURL:
func (c *estClient) buildURL(path string) string {
    base := fmt.Sprintf("%s://%s:%d", scheme, host, port)
    if c.cfg.Label != "" {
        base += "/" + c.cfg.Label
    }
    return base + path
}
```

**TDD:**
1. Test `buildURL` without label: `https://est.example.com:443/simpleenroll`
2. Test `buildURL` with label: `https://est.example.com:443/mylabel/simpleenroll`

---

### Task 4: Implement client certificate retrieval for re-enrollment
**Problem:** `PhaseEnrolling` has a `// TODO: retrieve client certificate from previous issuance` comment. When `Spec.Renewal == true`, `SimpleReenroll` is called but no client certificate is provided for TLS client auth, so it will fail.

**Files:**
- Modify: `api/v1alpha1/estorder_types.go` — add fields to `EstOrderStatus` for storing the issued certificate and private key (or a reference to a Secret)
- Modify: `internal/controller/estorder_controller.go` — after enrollment, store the certificate and key; before re-enrollment, retrieve and configure `estclient.Config.Cert` and `estclient.Config.Key`
- Test: `internal/controller/slice4_test.go` — add `TestEstOrderReconciler_ReenrollmentWithClientCert`

**Design decision:** Store the private key in a Kubernetes Secret owned by the EstOrder, referenced from `EstOrder.Status`. This avoids storing secrets in the CRD status.

---

## P2 — Reliability & Testing

### Task 5: Create kind-based E2E test harness
**Problem:** No integration tests exist that verify the operator works end-to-end in a real Kubernetes cluster with cert-manager installed.

**Files:**
- Create: `test/e2e/e2e_suite_test.go` — kind cluster setup with cert-manager
- Create: `test/e2e/e2e_test.go` — E2E tests:
  1. Deploy EstIssuer → verify Ready condition
  2. Create CertificateRequest → verify EstOrder created → verify certificate issued
  3. Test with Secret-based credentials
  4. Test recovery path (expired cert)

**Prerequisites:** Docker, kind, kubectl in CI

**Effort:** 4-8 hours

---

### Task 6: CACerts refresh reconciliation (Adversarial Hardening 3.1)
**Problem:** The operator fetches `/cacerts` during `EstIssuer` connectivity checks but doesn't persist or periodically refresh the TA database. If the portal rotates its CA, the operator won't notice until the next reconciliation.

**Files:**
- Modify: `internal/controller/estissuer_controller.go` — store fetched CA certs in `EstIssuer.Status` or a ConfigMap
- Add: periodic re-reconciliation via `RequeueAfter` (e.g., every 24 hours)
- Modify: `internal/estclient/client.go` — allow dynamic CA cert updates

**Effort:** 2-3 hours

---

## P3 — CI/CD

### Task 7: CI pipeline (Docker build, image push, test)
**Problem:** No CI/CD pipeline for building Docker images, running tests, or pushing to a registry.

**Files:**
- Create: `.github/workflows/ci.yaml` — lint, test, build Docker image
- Create: `.github/workflows/release.yaml` — tag-triggered image push
- Modify: `Makefile` — add `docker-push` target

**Effort:** 2-4 hours

---

### Task 8: Python operator parity check
**Problem:** The Go operator must handle the same `EstIssuer` manifests as the Python operator. No automated comparison exists.

**Files:**
- Create: `hack/parity-check.sh` — script that applies the same manifests to both operators and compares status output
- Or: Create: `test/parity/parity_test.go` — Go test that applies sample manifests and verifies equivalent behavior

**Effort:** 3-5 hours

---

## Optional (Deferred)

### Task 9: CMC support
**Problem:** RFC 7030 Appendix A describes CMC (CMS over CMS) for enrollment, but this is listed as optional in the plan.

**Effort:** 5-8 hours. Requires ASN.1 CMS parsing library. Defer unless explicitly requested.

### Task 10: Server-side key generation
**Problem:** RFC 7030 §4.4 describes server-side key generation as an optional flow. Not currently implemented.

**Effort:** 4-6 hours. Defer unless explicitly requested.