# Go Rewrite Phase 1: Project Foundation & CRD Definitions

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Initialize the Go project and implement the `EstIssuer` and `EstOrder` API types with basic reconciliation.

**Architecture:** Kubebuilder-based operator. `EstIssuer` and `EstOrder` will be the primary custom resources. The `EstIssuer` controller will handle trust anchor validation and connectivity.

**Tech Stack:** Go 1.26, Kubebuilder, controller-runtime, Kindle/Skaffold for testing.

---

### Task 1: Initialize Kubebuilder Project
**TDD scenario:** Trivial change — project initialization.

**Files:**
- Create: `est-operator-go/` (Project Root)

**Step 1: Initialize project**
Run: `kubebuilder init --domain est.mitre.org --repo est-operator-go`
Expected: Project structure created with `main.go` and `config/`.

**Step 2: Verify initialization**
Run: `ls -R est-operator-go/`
Expected: Presence of `api/`, `internal/controller/`, and `go.mod`.

**Step 3: Commit**
```bash
git add est-operator-go/
git commit -m "chore: initialize kubebuilder project for go rewrite"
```

---

### Task 2: Define EstIssuer API (with Root Pin)
**TDD scenario:** New feature — define API structure.

**Files:**
- Create: `est-operator-go/api/v1alpha1/estissuer_types.go`

**Step 1: Implement EstIssuerSpec**
```go
type EstIssuerSpec struct {
    Host       string `json:"host"`
    Port       int32  `json:"port"`
    Label      string `json:"label"`
    CAcert     string `json:"cacert"` // Base64 PEM
    RootPin    string `json:"rootPin"` // Required for Adversarial Hardening 3.1
    SecretName string `json:"secretName"`
}
```

**Step 2: Generate manifests**
Run: `make manifests`
Expected: `config/crd/bases/est.mitre.org_estissuers.yaml` created.

**Step 3: Commit**
```bash
git add est-operator-go/api/v1alpha1/estissuer_types.go
git commit -m "feat: define EstIssuer API with RootPin"
```

---

### Task 3: Define EstOrder API (with CSR Hash)
**TDD scenario:** New feature — define API structure.

**Files:**
- Create: `est-operator-go/api/v1alpha1/estorder_types.go`

**Step 1: Implement EstOrderSpec and Status**
```go
type EstOrderSpec struct {
    IssuerRef  IssuerRef     `json:"issuerRef"`
    Request    string        `json:"request"` // Base64 PEM CSR
    CSRHash    string        `json:"csrHash"` // Required for Adversarial Hardening 3.2
}

type EstOrderStatus struct {
    Phase   string `json:"phase"` // Pending, QueryingAttributes, Enrolling, Issued, Recovery, Failed
    Message string `json:"message"`
}
```

**Step 2: Generate manifests**
Run: `make manifests`
Expected: `config/crd/bases/est.mitre.org_estorders.yaml` created.

**Step 3: Commit**
```bash
git add est-operator-go/api/v1alpha1/estorder_types.go
git commit -m "feat: define EstOrder API with CSRHash and Phase state machine"
```

---

### Task 4: Implement Basic EstIssuer Connectivity Check
**TDD scenario:** New feature — full TDD cycle.

**Files:**
- Modify: `est-operator-go/internal/controller/estissuer_controller.go`
- Test: `est-operator-go/internal/controller/estissuer_controller_test.go`

**Step 1: Write the failing test**
```go
func TestReconcile_ConnectivityCheck(t *testing.T) {
    // Setup mock client and EstIssuer with valid host
    // Assert that the status is updated to 'Ready' after a successful ping/TCP check
}
```

**Step 2: Run test to verify it fails**
Run: `go test ./internal/controller/...`
Expected: FAIL (Implementation missing)

**Step 3: Write minimal implementation**
Implement `Reconcile` logic to check if `Host:Port` is reachable via TCP.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/controller/...`
Expected: PASS

**Step 5: Commit**
```bash
git add est-operator-go/internal/controller/estissuer_controller.go est-operator-go/internal/controller/estissuer_controller_test.go
git commit -m "feat: implement basic connectivity check for EstIssuer"
```

---

### Task 5: Implement TA Validation Logic (Adversarial Hardening 3.1)
**TDD scenario:** New feature — full TDD cycle.

**Files:**
- Modify: `est-operator-go/internal/controller/estissuer_controller.go`
- Test: `est-operator-go/internal/controller/estissuer_controller_test.go`

**Step 1: Write the failing test**
```go
func TestReconcile_RootPinValidation(t *testing.T) {
    // Mock /cacerts response with a cert NOT signed by the RootPin
    // Assert that the Issuer status is updated to 'NotReady' and security alert condition is emitted
}
```

**Step 2: Run test to verify it fails**
Run: `go test ./internal/controller/...`
Expected: FAIL

**Step 3: Write minimal implementation**
- Fetch `/cacerts`.
- Verify the returned CA chain against the `RootPin` provided in the spec.

**Step 4: Run test to verify it passes**
Run: `go test ./internal/controller/...`
Expected: PASS

**Step 5: Commit**
```bash
git add est-operator-go/internal/controller/estissuer_controller.go
git commit -m "feat: implement RootPin validation for Trust Anchor rotation"
```
