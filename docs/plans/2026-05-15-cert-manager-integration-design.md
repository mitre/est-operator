# Slice 4: Cert-Manager Integration Design

## Overview
This phase connects the `est-operator` Go implementation to `cert-manager`'s `CertificateRequest` resources and implements secure credential retrieval for the EST enrollment process.

## Components

### 1. CertificateRequestReconciler
- **Responsibility**: Watch `cert-manager.io/v1` `CertificateRequest` resources.
- **Logic**:
  - Filter for `issuerRef.group == "est.mitre.org"`.
  - Create a corresponding `EstOrder` resource in the same namespace.
  - Set `CertificateRequest` as the owner of `EstOrder`.
  - Update `CertificateRequest` status to `Ready=False, Reason=Pending`.
- **Implementation**: Relocated to `internal/controller/certificaterequest_controller.go`.

### 2. EstOrderReconciler Secret Retrieval
- **Responsibility**: Retrieve credentials for the EST portal.
- **Logic**:
  - Based on the `IssuerRef` in `EstOrder`:
    - If `EstIssuer`: use the issuer's namespace.
    - If `EstClusterIssuer`: use the operator's namespace (via `CLUSTER_SCOPE_NAMESPACE` or default `"est-operator"`).
  - Fetch the `Secret` specified in `EstIssuer.Spec.SecretName`.
  - Validate `Secret.Type == "kubernetes.io/basic-auth"`.
  - Decode `username` and `password`.
- **Integration**: Use these credentials when creating the `estclient.Config` during `PhaseEnrolling`.

### 3. Data Flow
`CertificateRequest` $\rightarrow$ `CertificateRequestReconciler` $\rightarrow$ `EstOrder` $\rightarrow$ `EstOrderReconciler` $\rightarrow$ `EstIssuer/Secret` $\rightarrow$ `estclient` $\rightarrow$ EST Portal $\rightarrow$ `CertificateRequest` (Status: Issued).

## Testing Plan
- Unit tests for `EstOrderReconciler` using a mock client to verify secret lookup.
- E2E test verifying that a `CertificateRequest` triggers an `EstOrder` and successfully completes (using a mock EST portal).
