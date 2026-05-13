# Design: Go Rewrite with Adversarial Hardening
Date: 2026-05-12
Topic: Hardening the est-operator Go rewrite against protocol and state failures.

## 1. Context
This design extends the goals laid out in `M001-REWRITE-TO-GO.md`. While the primary goal is a transition from Python (Kopf) to Go (controller-runtime), this document captures critical security and reliability hardening required to ensure the operator is production-ready and RFC 7030 compliant.

## 2. Core Objectives
- Transition to Go 1.26 for performance and concurrency.
- Implement full RFC 7030 compliance (Channel Binding, CSR Attributes).
- Mitigate specific failure modes identified during adversarial review.

## 3. Hardening Requirements

### 3.1 Trust Anchor Pinning & Verified Rotation
**Problem:** Dynamic updating of the TA database via `/cacerts` can lead to remote trust injection if the portal or connection is compromised.
**Requirement:** 
- Implement a "Root Pin" in the `EstIssuer` / `EstClusterIssuer` specification.
- The operator shall fetch updated CA chains from `/cacerts`.
- The operator MUST verify that any new certificate in the chain is signed by the pinned root before updating the internal TA database used for TLS verification.
- If verification fails, the operator must mark the Issuer as `NotReady` and emit a `SecurityAlert` condition.

### 3.2 Idempotent Enrollment via CSR Hashing
**Problem:** Operator crashes during the enrollment window can result in multiple certificates being issued for a single `CertificateRequest`, causing "cert leakage" and audit issues.
**Requirement:** 
- The `EstOrder` resource shall store a cryptographic hash of the CSR from the `CertificateRequest`.
- Before calling `/simpleenroll` or `/simplereenroll`, the operator shall check the `EstOrder` status and, if possible, query the portal (or use the hash as an idempotency key) to determine if a certificate has already been issued for this specific CSR.
- The state machine must transition to `Issued` only after the issued certificate is successfully persisted to the `CertificateRequest` status.

### 3.3 Proactive "Grace Period" State Machine
**Problem:** Expiration of the client certificate used for `/simplereenroll` creates a deadlock where the operator cannot authenticate to renew the certificate it needs to authenticate.
**Requirement:**
- Implement an expiration monitor for the current issued certificate.
- Define a "Recovery" state in the `EstOrder` state machine.
- If the current certificate is expired or within a critical window (e.g., < 24 hours), the operator shall:
    1. Attempt to fall back to the initial bootstrap credentials (Basic Auth) if configured.
    2. If fallback fails, emit a `Critical` condition on the `CertificateRequest` requesting manual administrative intervention (e.g., updating bootstrap secrets).

## 4. Updated Order State Machine
`Pending` $\rightarrow$ `QueryingAttributes` $\rightarrow$ `Enrolling` $\rightarrow$ `Issued`
*Added Transitions:*
- `Enrolling` $\rightarrow$ `Recovery` (on Auth Failure/Expiration)
- `Recovery` $\rightarrow$ `Enrolling` (on Bootstrap Success)
- `Any` $\rightarrow$ `Failed` (Terminal state with Error Condition)
