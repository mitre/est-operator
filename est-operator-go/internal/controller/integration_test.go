package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
	"git.mitre.org/est-operator/internal/estclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestIntegration_CertificateRequestCreatesEstOrderWithCSRHash(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	csrData := []byte("integration-test-csr-data")
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrData,
	})

	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "integration-certreq",
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

	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "integration-certreq", Namespace: "default"},
	})
	assert.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify EstOrder was created with CSRHash
	order := &estv1alpha1.EstOrder{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "integration-certreq-order", Namespace: "default"}, order)
	assert.NoError(t, err)
	assert.Equal(t, "est-issuer", order.Spec.IssuerRef.Name)
	assert.Equal(t, "EstIssuer", order.Spec.IssuerRef.Kind)
	assert.NotEmpty(t, order.Spec.CSRHash, "CSRHash should be set for idempotent enrollment")
	assert.Equal(t, sha256Base64(certReq.Spec.Request), order.Spec.CSRHash)

	// Verify CertificateRequest status was patched to Pending
	updatedCertReq := &certmanager.CertificateRequest{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "integration-certreq", Namespace: "default"}, updatedCertReq)
	assert.NoError(t, err)

	foundPending := false
	for _, cond := range updatedCertReq.Status.Conditions {
		if cond.Type == certmanager.CertificateRequestConditionReady && cond.Reason == certmanager.CertificateRequestReasonPending {
			foundPending = true
		}
	}
	assert.True(t, foundPending, "CertificateRequest should have Pending condition")
}

func TestIntegration_EnrollmentFlowWithSecretResolution(t *testing.T) {
	s := newTestScheme()
	ctx := context.Background()

	issuer := &estv1alpha1.EstIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "est-issuer",
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

	// Create an EstOrder in Enrolling phase
	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "order-with-owner",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "cert-manager.io/v1",
					Kind:       "CertificateRequest",
					Name:       "parent-certreq",
					Controller: ptrBool(true),
				},
			},
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  "est-issuer",
				Kind:  "EstIssuer",
				Group: "est.mitre.org",
			},
			CSRHash: "some-hash-value",
		},
		Status: estv1alpha1.EstOrderStatus{
			Phase: estv1alpha1.PhaseEnrolling,
		},
	}

	// Create parent CertificateRequest
	certReq := &certmanager.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "parent-certreq",
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(order, issuer, secret, certReq).
		WithStatusSubresource(order, certReq).
		Build()

	mockClient := new(MockEstClient)
	mockFactory := new(MockClientFactory)

	mockFactory.On("NewClient", mock.MatchedBy(func(cfg *estclient.Config) bool {
		return cfg.Username == "testuser" && cfg.Password == "testpass"
	})).Return(mockClient, nil)
	mockClient.On("GetTLSUnique", mock.Anything).Return([]byte("tls-unique"), nil)
	mockClient.On("SimpleEnroll", mock.Anything, mock.Anything).Return(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("enrolled-cert")}),
		nil,
	)
	mockClient.On("ExtractCertificates", mock.Anything).Return(
		[]*x509.Certificate{
			{Raw: []byte("leaf-cert-raw")},
			{Raw: []byte("ca-cert-raw")},
		},
		nil,
	)

	reconciler := &EstOrderReconciler{
		Client:        fakeClient,
		Scheme:        s,
		ClientFactory: mockFactory,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "order-with-owner", Namespace: "default"},
	})
	assert.NoError(t, err)
	assert.False(t, result.Requeue)

	// Verify EstOrder reached Issued phase with certificate data
	issuedOrder := &estv1alpha1.EstOrder{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "order-with-owner", Namespace: "default"}, issuedOrder)
	assert.NoError(t, err)
	assert.Equal(t, estv1alpha1.PhaseIssued, issuedOrder.Status.Phase)
	assert.NotEmpty(t, issuedOrder.Status.Certificate, "Certificate should be populated after enrollment")
	assert.NotEmpty(t, issuedOrder.Status.CA, "CA chain should be populated after enrollment")

	// Verify CertificateRequest was patched with the issued certificate
	patchedCertReq := &certmanager.CertificateRequest{}
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "parent-certreq", Namespace: "default"}, patchedCertReq)
	assert.NoError(t, err)
	assert.NotEmpty(t, patchedCertReq.Status.Certificate, "CertificateRequest should have certificate data")

	foundIssued := false
	for _, cond := range patchedCertReq.Status.Conditions {
		if cond.Type == certmanager.CertificateRequestConditionReady && cond.Status == cmmeta.ConditionTrue {
			foundIssued = true
			assert.Equal(t, certmanager.CertificateRequestReasonIssued, cond.Reason)
		}
	}
	assert.True(t, foundIssued, "CertificateRequest should have Ready=True/Issued condition")
}