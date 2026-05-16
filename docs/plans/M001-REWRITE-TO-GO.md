# M001: Rewrite est-operator to Golang 1.26

## Goal
Rewrite the `est-operator` from Python (Kopf) to Golang 1.26 using `controller-runtime` to improve performance, reliability, and RFC 7030 compliance.

## Architectural Changes

### 1. Ecosystem Transition
- **Framework**: Move from Kopf (Python) $\rightarrow$ Kubebuilder/Controller-Runtime (Go).
- **Concurrency**: Replace Kopf's event-driven singleton handlers with Go's concurrent reconciling loops.
- **State Management**: Move from relying on Kopf's `TemporaryError` delays to an explicit `Status` state machine in the `EstOrder` CRD.

### 2. RFC 7030 Compliance Enhancements
- **Channel Binding**: Implement `tls-unique` extraction from the TLS handshake and integration into the CSR `challengePassword` field.
- **CSR Attribute Negotiation**: Implement a pre-enrollment phase that calls `/.well-known/est/csrattrs` and updates the CSR based on the response.
- **Dynamic Trust Anchors**: Implement a background reconciliation for `EstIssuer` to keep the local TA database synchronized with the portal's `/cacerts`.

## Implementation Slices (Tracer Bullets)

### Slice 1: Project Foundation & CRD Definitions
- Initialize Go project with Kubebuilder.
- Define `EstIssuer` and `EstOrder` Go types (matching or extending the current manifests).
- Implement basic `EstIssuer` reconciliation (validation of connectivity).

### Slice 2: The EST Protocol Client (The Core)
- Build a robust EST client library in Go.
- Implement ASN.1 encoding/decoding for PKCS#10 and PKCS#7.
- Implement `tls-unique` capture using `crypto/tls` (ConnectionState).
- Implement the `/cacerts` fetcher and trust anchor validator.

### Slice 3: Enrollment Workflow (State Machine)
- Implement the `CertificateRequest` $\rightarrow$ `EstOrder` trigger.
- Implement the `EstOrder` state machine:
    - `Pending` $\rightarrow$ `QueryingAttributes` $\rightarrow$ `Enrolling` $\rightarrow$ `Issued`.
- Implement the `/simpleenroll` and `/simplereenroll` HTTPS exchanges.

### Slice 4: Cert-Manager Integration
- Logic to patch the `CertificateRequest` status with the issued certificate and CA chain.
- Implement proper ownership and garbage collection using K8s `OwnerReferences`.

### Slice 5: Advanced Features & Hardening
- Full CMC support (Optional).
- Server-side key generation (Optional).
- FIPS 140-2 compliance via `boringcrypto` or similar Go toolchains if required (matching the `Dockerfile.fips` logic).
- Comprehensive integration testing using a mock EST server.

## Verification Strategy
- **Unit Tests**: Mock the EST portal API.
- **End-to-End Testing**:
    - Spin up a `kind` cluster.
    - Install `cert-manager`.
    - Use `Skaffold` to deploy the Go operator into the cluster.
    - Verify issuance against `http://testrfc7030.com/`.
- **Parity Check**: Ensure the Go operator handles the same `EstIssuer` manifests as the Python operator.

## Constraints
- Must use Golang 1.26.
- Must maintain compatibility with existing `est.mitre.org/v1alpha1` CRDs (or provide a migration path).

## Development & Testing Constraints
- **Host Environment**: Development machine is non-Linux. Any tests requiring a Linux environment must run in containers.
- **Tooling**:
    - **Docker**: Available and used for all containerized operations.
    - **Kubernetes**: Use `kind` (Kubernetes in Docker) for local cluster testing.
    - **Deployment**: Use `Skaffold` for the build-deploy-test loop.
- **External Dependencies**:
    - **EST Server**: Use `http://testrfc7030.com/` as the primary EST server for end-to-end testing.
    - **Cluster Add-ons**: `cert-manager` must be installed in the `kind` cluster.
