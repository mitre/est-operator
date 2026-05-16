package controller

import (
	"context"
	"testing"
	"crypto/x509"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
	"git.mitre.org/est-operator/internal/estclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sclientscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MockEstClient is a mock implementation of estclient.Client
type MockEstClient struct {
	mock.Mock
}

func (m *MockEstClient) FetchCACerts(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEstClient) FetchCSRAttributes(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEstClient) SimpleEnroll(ctx context.Context, csr []byte) ([]byte, error) {
	args := m.Called(ctx, csr)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEstClient) SimpleReenroll(ctx context.Context, csr []byte) ([]byte, error) {
	args := m.Called(ctx, csr)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEstClient) GetTLSUnique(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockEstClient) ExtractCertificates(bundle []byte) ([]*x509.Certificate, error) {
	args := m.Called(bundle)
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}

// MockClientFactory is a mock implementation of estclient.ClientFactory
type MockClientFactory struct {
	mock.Mock
}

func (m *MockClientFactory) NewClient(cfg *estclient.Config) (estclient.Client, error) {
	args := m.Called(cfg)
	return args.Get(0).(estclient.Client), args.Error(1)
}

func TestEstOrderWorkflow(t *testing.T) {
	s := runtime.NewScheme()
	_ = k8sclientscheme.AddToScheme(s)
	estv1alpha1.AddToScheme(s)

	ctx := context.Background()

	t.Run("State Transition: Pending -> QueryingAttributes", func(t *testing.T) {
		order := &estv1alpha1.EstOrder{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EstOrder",
				APIVersion: "est.mitre.org/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-order",
				Namespace: "default",
			},
			Status: estv1alpha1.EstOrderStatus{
				Phase: estv1alpha1.PhasePending,
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&estv1alpha1.EstOrder{}).Build()
		if err := fakeClient.Create(ctx, order); err != nil {
			t.Fatalf("failed to create order: %v", err)
		}

		mockFactory := new(MockClientFactory)

		reconciler := &EstOrderReconciler{
			Client:       fakeClient,
			Scheme:       s,
			ClientFactory: mockFactory,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "test-order",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		assert.NoError(t, err)
		assert.True(t, result.Requeue)

		updatedOrder := &estv1alpha1.EstOrder{}
		err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-order"}, updatedOrder)
		assert.NoError(t, err)
		assert.Equal(t, estv1alpha1.PhaseQueryingAttributes, updatedOrder.Status.Phase)
	})

	t.Run("State Transition: QueryingAttributes -> Enrolling", func(t *testing.T) {
		order := &estv1alpha1.EstOrder{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EstOrder",
				APIVersion: "est.mitre.org/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-order",
				Namespace: "default",
			},
			Spec: estv1alpha1.EstOrderSpec{
				IssuerRef: estv1alpha1.IssuerRef{
					Name: "test-issuer",
					Kind: "EstIssuer",
				},
			},
			Status: estv1alpha1.EstOrderStatus{
				Phase: estv1alpha1.PhaseQueryingAttributes,
			},
		}
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
				Host: "est.example.com",
				Port: 443,
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&estv1alpha1.EstOrder{}).Build()
		if err := fakeClient.Create(ctx, order); err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		if err := fakeClient.Create(ctx, issuer); err != nil {
			t.Fatalf("failed to create issuer: %v", err)
		}

		mockClient := new(MockEstClient)
		mockFactory := new(MockClientFactory)

		mockFactory.On("NewClient", mock.Anything).Return(mockClient, nil)
		mockClient.On("FetchCSRAttributes", mock.Anything).Return([]byte("mock-attrs"), nil)

		reconciler := &EstOrderReconciler{
			Client:       fakeClient,
			Scheme:       s,
			ClientFactory: mockFactory,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "test-order",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		assert.NoError(t, err)
		assert.True(t, result.Requeue)

		updatedOrder := &estv1alpha1.EstOrder{}
		err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-order"}, updatedOrder)
		assert.NoError(t, err)
		assert.Equal(t, estv1alpha1.PhaseEnrolling, updatedOrder.Status.Phase)
		assert.Equal(t, "mock-attrs", updatedOrder.Status.Attributes)
	})

	t.Run("State Transition: Enrolling -> Issued", func(t *testing.T) {
		order := &estv1alpha1.EstOrder{
			TypeMeta: metav1.TypeMeta{
				Kind:       "EstOrder",
				APIVersion: "est.mitre.org/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-order",
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
				Host: "est.example.com",
				Port: 443,
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&estv1alpha1.EstOrder{}).Build()
		if err := fakeClient.Create(ctx, order); err != nil {
			t.Fatalf("failed to create order: %v", err)
		}
		if err := fakeClient.Create(ctx, issuer); err != nil {
			t.Fatalf("failed to create issuer: %v", err)
		}

		mockClient := new(MockEstClient)
		mockFactory := new(MockClientFactory)

		mockFactory.On("NewClient", mock.Anything).Return(mockClient, nil)
		mockClient.On("GetTLSUnique", mock.Anything).Return([]byte("tls-unique"), nil)
		mockClient.On("SimpleEnroll", mock.Anything, mock.Anything).Return([]byte("cert-bundle"), nil)
		mockClient.On("ExtractCertificates", []byte("cert-bundle")).Return([]*x509.Certificate{{Raw: []byte("cert-raw")}}, nil)

		reconciler := &EstOrderReconciler{
			Client:       fakeClient,
			Scheme:       s,
			ClientFactory: mockFactory,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "test-order",
			},
		}

		result, err := reconciler.Reconcile(ctx, req)
		assert.NoError(t, err)
		assert.False(t, result.Requeue)

		updatedOrder := &estv1alpha1.EstOrder{}
		err = fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "test-order"}, updatedOrder)
		assert.NoError(t, err)
		assert.Equal(t, estv1alpha1.PhaseIssued, updatedOrder.Status.Phase)
		assert.NotEmpty(t, updatedOrder.Status.Certificate)
	})
}
