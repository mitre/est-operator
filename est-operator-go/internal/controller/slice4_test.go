package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sclientscheme "k8s.io/client-go/kubernetes/scheme"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
	"git.mitre.org/est-operator/internal/estclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = k8sclientscheme.AddToScheme(s)
	_ = estv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	_ = certmanager.AddToScheme(s)
	return s
}

// --- Secret credential retrieval tests ---

func TestGetCredentialsFromSecret_BasicAuth(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-credentials",
			Namespace: "default",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("s3cret"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(secret).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	username, password, err := reconciler.getCredentialsFromSecret(ctx, "est-credentials", "default")
	assert.NoError(t, err)
	assert.Equal(t, "admin", username)
	assert.Equal(t, "s3cret", password)
}

func TestGetCredentialsFromSecret_WrongType(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-credentials",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("s3cret"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(secret).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	_, _, err := reconciler.getCredentialsFromSecret(ctx, "est-credentials", "default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be of type kubernetes.io/basic-auth")
}

func TestGetCredentialsFromSecret_EmptySecretName(t *testing.T) {
	s := newTestScheme()
	reconciler := &EstOrderReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).Build(),
		Scheme: s,
	}

	username, password, err := reconciler.getCredentialsFromSecret(context.Background(), "", "default")
	assert.NoError(t, err)
	assert.Equal(t, "", username)
	assert.Equal(t, "", password)
}

func TestGetCredentialsFromSecret_NotFound(t *testing.T) {
	s := newTestScheme()
	reconciler := &EstOrderReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).Build(),
		Scheme: s,
	}

	_, _, err := reconciler.getCredentialsFromSecret(context.Background(), "nonexistent", "default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch Secret")
}

func TestGetCredentialsFromSecret_PlainText(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-credentials",
			Namespace: "default",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("s3cret"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(secret).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	username, password, err := reconciler.getCredentialsFromSecret(ctx, "est-credentials", "default")
	assert.NoError(t, err)
	assert.Equal(t, "admin", username)
	assert.Equal(t, "s3cret", password)
}

// --- Issuer resolution tests ---

func TestResolveIssuerConfig_EstIssuer(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	issuer := &estv1alpha1.EstIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "test-ns",
		},
		Spec: estv1alpha1.EstIssuerSpec{
			Host: "est.example.com",
			Port: 443,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(issuer).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "test-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
		},
	}

	host, port, err := reconciler.resolveIssuerConfig(ctx, order)
	assert.NoError(t, err)
	assert.Equal(t, "est.example.com", host)
	assert.Equal(t, 443, port)
}

func TestResolveIssuerConfig_EstClusterIssuer(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	clusterIssuer := &estv1alpha1.EstClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-issuer",
		},
		Spec: estv1alpha1.EstClusterIssuerSpec{
			Host: "est.cluster.example.com",
			Port: 8443,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(clusterIssuer).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "test-cluster-issuer",
				Kind:  "EstClusterIssuer",
				Group: "est.mitre.org",
			},
		},
	}

	host, port, err := reconciler.resolveIssuerConfig(ctx, order)
	assert.NoError(t, err)
	assert.Equal(t, "est.cluster.example.com", host)
	assert.Equal(t, 8443, port)
}

func TestResolveIssuerWithCredentials_EstIssuer(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	issuer := &estv1alpha1.EstIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "test-ns",
		},
		Spec: estv1alpha1.EstIssuerSpec{
			Host:       "est.example.com",
			Port:       443,
			SecretName: "est-creds",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-creds",
			Namespace: "test-ns",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("s3cret"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(issuer, secret).Build()

	reconciler := &EstOrderReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "test-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
		},
	}

	host, port, username, password, err := reconciler.resolveIssuerWithCredentials(ctx, order)
	assert.NoError(t, err)
	assert.Equal(t, "est.example.com", host)
	assert.Equal(t, 443, port)
	assert.Equal(t, "admin", username)
	assert.Equal(t, "s3cret", password)
}

func TestResolveIssuerWithCredentials_EstClusterIssuer(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	clusterIssuer := &estv1alpha1.EstClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster-issuer",
		},
		Spec: estv1alpha1.EstClusterIssuerSpec{
			Host:       "est.cluster.example.com",
			Port:       8443,
			SecretName: "cluster-creds",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-creds",
			Namespace: "est-operator",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"username": []byte("cluster-admin"),
			"password": []byte("cluster-s3cret"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(clusterIssuer, secret).Build()

	reconciler := &EstOrderReconciler{
		Client:            fakeClient,
		Scheme:            s,
		OperatorNamespace: "est-operator",
	}

	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "some-other-ns",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "test-cluster-issuer",
				Kind:  "EstClusterIssuer",
				Group: "est.mitre.org",
			},
		},
	}

	host, port, username, password, err := reconciler.resolveIssuerWithCredentials(ctx, order)
	assert.NoError(t, err)
	assert.Equal(t, "est.cluster.example.com", host)
	assert.Equal(t, 8443, port)
	assert.Equal(t, "cluster-admin", username)
	assert.Equal(t, "cluster-s3cret", password)
}

func TestGetOperatorNamespace(t *testing.T) {
	reconciler := &EstOrderReconciler{}

	// Default
	assert.Equal(t, "est-operator", reconciler.getOperatorNamespace())

	// Explicit
	reconciler.OperatorNamespace = "my-namespace"
	assert.Equal(t, "my-namespace", reconciler.getOperatorNamespace())

	// Reset to test env
	reconciler.OperatorNamespace = ""
	t.Setenv(ClusterScopeNamespaceEnv, "env-namespace")
	assert.Equal(t, "env-namespace", reconciler.getOperatorNamespace())
}

// --- CertificateRequest reconciler tests ---

func TestCertificateRequestReconciler_FilterByGroup(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	// Create a CertificateRequest that references an issuer NOT in our group
	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq-wrong-group",
			Namespace: "default",
		},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "letsencrypt",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			},
			Request: []byte("MIIBkTCBzwIBADA..."),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(certReq).Build()

	reconciler := &CertificateRequestReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-certreq-wrong-group",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, false, result.Requeue)

	// Verify no EstOrder was created
	orders := &estv1alpha1.EstOrderList{}
	err = fakeClient.List(ctx, orders)
	assert.NoError(t, err)
	assert.Empty(t, orders.Items)
}

func TestCertificateRequestReconciler_CreatesEstOrder(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte("fake-csr"),
	})

	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq",
			Namespace: "default",
		},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "est-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			Request: csrPEM,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(certReq).
		WithStatusSubresource(certReq).
		Build()

	reconciler := &CertificateRequestReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-certreq",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, false, result.Requeue)

	// Verify EstOrder was created
	order := &estv1alpha1.EstOrder{}
	err = fakeClient.Get(ctx, types.NamespacedName{
		Name:      "test-certreq-order",
		Namespace: "default",
	}, order)
	assert.NoError(t, err)
	assert.Equal(t, "est-issuer", order.Spec.IssuerRef.Name)
	assert.Equal(t, "EstIssuer", order.Spec.IssuerRef.Kind)
	assert.Equal(t, "est.mitre.org", order.Spec.IssuerRef.Group)

	// Verify owner reference is set
	assert.NotEmpty(t, order.OwnerReferences)
	assert.Equal(t, "CertificateRequest", order.OwnerReferences[0].Kind)
	assert.Equal(t, "test-certreq", order.OwnerReferences[0].Name)
}

func TestCertificateRequestReconciler_SkipsAlreadyReady(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	now := metav1.Now()
	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq-ready",
			Namespace: "default",
		},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "est-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			Request: []byte("csr-data"),
		},
		Status: certmanager.CertificateRequestStatus{
			Conditions: []certmanager.CertificateRequestCondition{
				{
					Type:               certmanager.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionTrue,
					Reason:             certmanager.CertificateRequestReasonIssued,
					LastTransitionTime: &now,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(certReq).Build()

	reconciler := &CertificateRequestReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-certreq-ready",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, false, result.Requeue)

	// Verify no EstOrder was created
	orders := &estv1alpha1.EstOrderList{}
	err = fakeClient.List(ctx, orders)
	assert.NoError(t, err)
	assert.Empty(t, orders.Items)
}

func TestCertificateRequestReconciler_SkipsDenied(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	now := metav1.Now()
	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq-denied",
			Namespace: "default",
		},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "est-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			Request: []byte("csr-data"),
		},
		Status: certmanager.CertificateRequestStatus{
			Conditions: []certmanager.CertificateRequestCondition{
				{
					Type:               certmanager.CertificateRequestConditionReady,
					Status:             cmmeta.ConditionFalse,
					Reason:             certmanager.CertificateRequestReasonDenied,
					LastTransitionTime: &now,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(s).WithObjects(certReq).Build()

	reconciler := &CertificateRequestReconciler{
		Client: fakeClient,
		Scheme: s,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-certreq-denied",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, false, result.Requeue)

	orders := &estv1alpha1.EstOrderList{}
	err = fakeClient.List(ctx, orders)
	assert.NoError(t, err)
	assert.Empty(t, orders.Items)
}

// --- Patch CertificateRequest status test ---

func TestPatchCertificateRequest(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBkTCBzwIBADA...\n-----END CERTIFICATE-----\n"
	caPEM := "-----BEGIN CERTIFICATE-----\nCA CERT DATA...\n-----END CERTIFICATE-----\n"

	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq-patch",
			Namespace: "default",
		},
		Spec: certmanager.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "est-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			Request: []byte("csr-data"),
		},
	}

	// Create EstOrder with owner reference to the certReq
	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-certreq-patch-order",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "cert-manager.io/v1",
					Kind:       "CertificateRequest",
					Name:       "test-certreq-patch",
					Controller: ptrBool(true),
				},
			},
		},
		Status: estv1alpha1.EstOrderStatus{
			Phase:       estv1alpha1.PhaseIssued,
			Certificate: certPEM,
			CA:           caPEM,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(certReq, order).
		WithStatusSubresource(certReq).
		Build()

	reconciler := &EstOrderReconciler{
		Client:        fakeClient,
		Scheme:        s,
		ClientFactory: estclient.NewClientFactory(),
	}

	err := reconciler.patchCertificateRequest(ctx, order)
	assert.NoError(t, err)

	// Verify CertificateRequest was patched
	updatedCertReq := &certmanager.CertificateRequest{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-certreq-patch", Namespace: "default"}, updatedCertReq)
	assert.NoError(t, err)
	assert.Equal(t, []byte(certPEM), updatedCertReq.Status.Certificate)
	assert.Equal(t, []byte(caPEM), updatedCertReq.Status.CA)

	// Check Ready condition is True
	found := false
	for _, cond := range updatedCertReq.Status.Conditions {
		if cond.Type == certmanager.CertificateRequestConditionReady {
			assert.Equal(t, cmmeta.ConditionTrue, cond.Status)
			assert.Equal(t, certmanager.CertificateRequestReasonIssued, cond.Reason)
			found = true
		}
	}
	assert.True(t, found, "Expected Ready condition to be set on CertificateRequest")
}

func TestPatchCertificateRequest_NoOwner(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	// EstOrder with no owner references (standalone)
	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "standalone-order",
			Namespace: "default",
		},
		Status: estv1alpha1.EstOrderStatus{
			Phase:       estv1alpha1.PhaseIssued,
			Certificate: "cert-data",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(order).
		Build()

	reconciler := &EstOrderReconciler{
		Client:        fakeClient,
		Scheme:        s,
		ClientFactory: estclient.NewClientFactory(),
	}

	// Should not error, just log and return
	err := reconciler.patchCertificateRequest(ctx, order)
	assert.NoError(t, err)
}

// --- EstOrder State Transition tests with credentials ---

func TestEstOrderWorkflow_EnrollingWithSecret(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	issuer := &estv1alpha1.EstIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EstIssuer",
			APIVersion: "est.mitre.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-issuer",
			Namespace: "default",
		},
		Spec: estv1alpha1.EstIssuerSpec{
			Host:       "est.example.com",
			Port:       443,
			SecretName: "est-creds",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-creds",
			Namespace: "default",
		},
		Type: corev1.SecretTypeBasicAuth,
		Data: map[string][]byte{
			"username": []byte("testuser"),
			"password": []byte("testpass"),
		},
	}

	order := &estv1alpha1.EstOrder{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EstOrder",
			APIVersion: "est.mitre.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-order-enroll",
			Namespace: "default",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name: "test-issuer",
				Kind: "EstIssuer",
			},
		},
		Status: estv1alpha1.EstOrderStatus{
			Phase: estv1alpha1.PhaseEnrolling,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(order, issuer, secret).
		WithStatusSubresource(order).
		Build()

	mockClient := new(MockEstClient)
	mockFactory := new(MockClientFactory)

	// Expect the factory to be called with credentials
	mockFactory.On("NewClient", mock.Anything).Return(mockClient, nil)
	mockClient.On("GetTLSUnique", mock.Anything).Return([]byte("tls-unique"), nil)
	mockClient.On("SimpleEnroll", mock.Anything, mock.Anything).Return([]byte("cert-bundle"), nil)
	mockClient.On("ExtractCertificates", []byte("cert-bundle")).Return([]*x509.Certificate{{Raw: []byte("cert-raw")}}, nil)

	reconciler := &EstOrderReconciler{
		Client:        fakeClient,
		Scheme:        s,
		ClientFactory: mockFactory,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-order-enroll",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.False(t, result.Requeue)

	updatedOrder := &estv1alpha1.EstOrder{}
	err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-order-enroll"}, updatedOrder)
	assert.NoError(t, err)
	assert.Equal(t, estv1alpha1.PhaseIssued, updatedOrder.Status.Phase)
	assert.NotEmpty(t, updatedOrder.Status.Certificate)

	// Verify that the mock factory was called with the correct credentials
	mockFactory.AssertCalled(t, "NewClient", mock.MatchedBy(func(cfg *estclient.Config) bool {
		return cfg.Username == "testuser" && cfg.Password == "testpass"
	}))
}

func TestEstOrderWorkflow_PendingTransition(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	order := &estv1alpha1.EstOrder{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EstOrder",
			APIVersion: "est.mitre.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-order-pending",
			Namespace: "default",
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "test-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			Request: "base64csr",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(order).
		WithStatusSubresource(order).
		Build()

	reconciler := &EstOrderReconciler{
		Client:        fakeClient,
		Scheme:        s,
		ClientFactory: new(MockClientFactory),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "test-order-pending",
		},
	}

	// Empty phase should transition to Pending
	result, err := reconciler.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.True(t, result.Requeue)

	updatedOrder := &estv1alpha1.EstOrder{}
	err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-order-pending"}, updatedOrder)
	assert.NoError(t, err)
	assert.Equal(t, estv1alpha1.PhasePending, updatedOrder.Status.Phase)
}

// --- CSR Hash test ---

func TestCSRHashGeneration(t *testing.T) {
	csrData := []byte("test-csr-data")
	hash := sha256.Sum256(csrData)
	hashStr := base64.StdEncoding.EncodeToString(hash[:])
	assert.NotEmpty(t, hashStr)

	// Verify the hash is deterministic
	hash2 := sha256.Sum256(csrData)
	hash2Str := base64.StdEncoding.EncodeToString(hash2[:])
	assert.Equal(t, hashStr, hash2Str)
}

// --- Helper ---

func ptrBool(b bool) *bool {
	return &b
}