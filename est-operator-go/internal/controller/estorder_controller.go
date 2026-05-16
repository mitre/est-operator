/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
	"git.mitre.org/est-operator/internal/estclient"
)

const (
	// ClusterScopeNamespaceEnv is the environment variable used to configure the
	// namespace where the operator looks up Secrets for EstClusterIssuer resources.
	// Defaults to "est-operator" if not set.
	ClusterScopeNamespaceEnv = "CLUSTER_SCOPE_NAMESPACE"
	DefaultClusterNamespace  = "est-operator"

	// SecretTypeBasicAuth is the Kubernetes secret type for basic authentication.
	SecretTypeBasicAuth = "kubernetes.io/basic-auth"
)

// EstOrderReconciler reconciles a EstOrder object
type EstOrderReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	ClientFactory      estclient.ClientFactory
	OperatorNamespace  string // namespace for cluster-scoped issuer secret lookups; defaults to CLUSTER_SCOPE_NAMESPACE env or "est-operator"
}

// +kubebuilder:rbac:groups=est.mitre.org,resources=estorders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=est.mitre.org,resources=estorders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=est.mitre.org,resources=estorders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *EstOrderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the EstOrder instance
	estOrder := &estv1alpha1.EstOrder{}
	err := r.Get(ctx, req.NamespacedName, estOrder)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// State machine
	phase := estOrder.Status.Phase
	switch phase {
	case "":
		// Initialize phase to Pending
		estOrder.Status.Phase = estv1alpha1.PhasePending
		estOrder.Status.Message = "Order initialized"
		if err := r.Status().Update(ctx, estOrder); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Order initialized to Pending", "name", estOrder.Name)
		return ctrl.Result{Requeue: true}, nil

	case estv1alpha1.PhasePending:
		// Transition to QueryingAttributes
		estOrder.Status.Phase = estv1alpha1.PhaseQueryingAttributes
		estOrder.Status.Message = "Querying CSR attributes"
		if err := r.Status().Update(ctx, estOrder); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Order transitioning to QueryingAttributes", "name", estOrder.Name)
		return ctrl.Result{Requeue: true}, nil

	case estv1alpha1.PhaseQueryingAttributes:
		// Retrieve the Issuer and its credentials
		issuerHost, issuerPort, err := r.resolveIssuerConfig(ctx, estOrder)
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to resolve issuer config", err)
		}

		// Create EST client
		cfg := &estclient.Config{
			Host:   issuerHost,
			Port:   issuerPort,
			Scheme: "https",
		}
		cli, err := r.ClientFactory.NewClient(cfg)
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to create EST client", err)
		}

		// Fetch attributes
		attrs, err := cli.FetchCSRAttributes(ctx)
		if err != nil {
			log.Info("Failed to fetch attributes, proceeding to Enrolling anyway", "error", err)
			// We can proceed to Enrolling if attributes are optional or not supported by the portal
		} else {
			log.Info("Successfully fetched CSR attributes", "size", len(attrs))
			estOrder.Status.Attributes = string(attrs)
		}

		// Transition to Enrolling
		estOrder.Status.Phase = estv1alpha1.PhaseEnrolling
		estOrder.Status.Message = "Prepared for enrollment"
		if err := r.Status().Update(ctx, estOrder); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	case estv1alpha1.PhaseEnrolling:
		// Retrieve the Issuer and its credentials
		issuerHost, issuerPort, username, password, err := r.resolveIssuerWithCredentials(ctx, estOrder)
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to resolve issuer credentials", err)
		}

		// Create EST client with credentials
		cfg := &estclient.Config{
			Host:     issuerHost,
			Port:     issuerPort,
			Scheme:   "https",
			Username: username,
			Password: password,
		}
		cli, err := r.ClientFactory.NewClient(cfg)
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to create EST client", err)
		}

		// 1. Get tls-unique for channel binding
		tlsUnique, err := cli.GetTLSUnique(ctx)
		if err != nil {
			log.Error(err, "Failed to get tls-unique")
			return ctrl.Result{}, err
		}

		// 2. Generate CSR
		csr, _, err := estclient.GenerateCSR("est-operator", tlsUnique, []byte(estOrder.Status.Attributes))
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to generate CSR", err)
		}

		// 3. Perform enrollment
		var certBundle []byte
		if estOrder.Spec.Renewal {
			// Use SimpleReenroll with client certs
			// TODO: retrieve client certificate from previous issuance
			certBundle, err = cli.SimpleReenroll(ctx, csr)
		} else {
			certBundle, err = cli.SimpleEnroll(ctx, csr)
		}

		if err != nil {
			return r.failOrder(ctx, estOrder, "Enrollment failed", err)
		}

		// 4. Extract certificates
		certs, err := cli.ExtractCertificates(certBundle)
		if err != nil {
			return r.failOrder(ctx, estOrder, "Failed to extract certificates from bundle", err)
		}
		if len(certs) == 0 {
			return r.failOrder(ctx, estOrder, "No certificates found in bundle", fmt.Errorf("empty certificate list"))
		}

		// 5. Build the leaf cert PEM and CA chain PEM
		leafCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certs[0].Raw,
		})

		// Build CA chain PEM from remaining certificates
		var caChainPEM []byte
		for i := 1; i < len(certs); i++ {
			caChainPEM = append(caChainPEM, pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certs[i].Raw,
			})...)
		}

		estOrder.Status.Certificate = string(leafCertPEM)
		if len(caChainPEM) > 0 {
			estOrder.Status.CA = string(caChainPEM)
		}
		estOrder.Status.Phase = estv1alpha1.PhaseIssued
		estOrder.Status.Message = "Certificate issued successfully"

		if err := r.Status().Update(ctx, estOrder); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Order issued successfully", "name", estOrder.Name)

		// 6. Write issued certificate back to the owning CertificateRequest
		if err := r.patchCertificateRequest(ctx, estOrder); err != nil {
			log.Error(err, "Failed to patch owning CertificateRequest", "orderName", estOrder.Name)
			// Don't requeue; the certificate is stored on EstOrder and we can retry later
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil

	case estv1alpha1.PhaseIssued:
		log.Info("Order already issued", "name", estOrder.Name)
		return ctrl.Result{}, nil

	case estv1alpha1.PhaseFailed:
		log.Info("Order in Failed state", "name", estOrder.Name)
		return ctrl.Result{}, nil

	default:
		log.Info("Unknown phase", "phase", phase, "name", estOrder.Name)
		return ctrl.Result{}, nil
	}
}

// resolveIssuerConfig returns the host and port for the issuer referenced by the EstOrder.
func (r *EstOrderReconciler) resolveIssuerConfig(ctx context.Context, order *estv1alpha1.EstOrder) (string, int, error) {
	issuerRef := order.Spec.IssuerRef

	switch issuerRef.Kind {
	case "EstClusterIssuer":
		clusterIssuer := &estv1alpha1.EstClusterIssuer{}
		if err := r.Get(ctx, types.NamespacedName{Name: issuerRef.Name}, clusterIssuer); err != nil {
			return "", 0, fmt.Errorf("failed to fetch EstClusterIssuer %s: %w", issuerRef.Name, err)
		}
		return clusterIssuer.Spec.Host, int(clusterIssuer.Spec.Port), nil

	case "EstIssuer", "":
		issuer := &estv1alpha1.EstIssuer{}
		if err := r.Get(ctx, types.NamespacedName{Name: issuerRef.Name, Namespace: order.Namespace}, issuer); err != nil {
			return "", 0, fmt.Errorf("failed to fetch EstIssuer %s/%s: %w", order.Namespace, issuerRef.Name, err)
		}
		return issuer.Spec.Host, int(issuer.Spec.Port), nil

	default:
		return "", 0, fmt.Errorf("unsupported issuer kind: %s", issuerRef.Kind)
	}
}

// resolveIssuerWithCredentials returns the host, port, username, and password for the issuer
// referenced by the EstOrder, by also reading the Secret if one is specified.
func (r *EstOrderReconciler) resolveIssuerWithCredentials(ctx context.Context, order *estv1alpha1.EstOrder) (string, int, string, string, error) {
	issuerRef := order.Spec.IssuerRef

	switch issuerRef.Kind {
	case "EstClusterIssuer":
		clusterIssuer := &estv1alpha1.EstClusterIssuer{}
		if err := r.Get(ctx, types.NamespacedName{Name: issuerRef.Name}, clusterIssuer); err != nil {
			return "", 0, "", "", fmt.Errorf("failed to fetch EstClusterIssuer %s: %w", issuerRef.Name, err)
		}

		username, password, err := r.getCredentialsFromSecret(ctx, clusterIssuer.Spec.SecretName, r.getOperatorNamespace())
		if err != nil {
			return "", 0, "", "", fmt.Errorf("failed to get credentials for EstClusterIssuer %s: %w", issuerRef.Name, err)
		}

		return clusterIssuer.Spec.Host, int(clusterIssuer.Spec.Port), username, password, nil

	case "EstIssuer", "":
		issuer := &estv1alpha1.EstIssuer{}
		if err := r.Get(ctx, types.NamespacedName{Name: issuerRef.Name, Namespace: order.Namespace}, issuer); err != nil {
			return "", 0, "", "", fmt.Errorf("failed to fetch EstIssuer %s/%s: %w", order.Namespace, issuerRef.Name, err)
		}

		username, password, err := r.getCredentialsFromSecret(ctx, issuer.Spec.SecretName, order.Namespace)
		if err != nil {
			return "", 0, "", "", fmt.Errorf("failed to get credentials for EstIssuer %s/%s: %w", order.Namespace, issuerRef.Name, err)
		}

		return issuer.Spec.Host, int(issuer.Spec.Port), username, password, nil

	default:
		return "", 0, "", "", fmt.Errorf("unsupported issuer kind: %s", issuerRef.Kind)
	}
}

// getOperatorNamespace returns the namespace used for cluster-scoped issuer secret lookups.
func (r *EstOrderReconciler) getOperatorNamespace() string {
	if r.OperatorNamespace != "" {
		return r.OperatorNamespace
	}
	if ns := os.Getenv(ClusterScopeNamespaceEnv); ns != "" {
		return ns
	}
	return DefaultClusterNamespace
}

// getCredentialsFromSecret fetches and decodes credentials from a Secret of type kubernetes.io/basic-auth.
func (r *EstOrderReconciler) getCredentialsFromSecret(ctx context.Context, secretName, namespace string) (string, string, error) {
	if secretName == "" {
		return "", "", nil // No secret configured, enroll without basic auth
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return "", "", fmt.Errorf("failed to fetch Secret %s/%s: %w", namespace, secretName, err)
	}

	if secret.Type != SecretTypeBasicAuth {
		return "", "", fmt.Errorf("Secret %s/%s must be of type %s, got %s", namespace, secretName, SecretTypeBasicAuth, secret.Type)
	}

	username := string(secret.Data["username"])
	password := string(secret.Data["password"])

	if username == "" {
		// Try base64-decoded form for compatibility
		if raw, ok := secret.Data["username"]; ok {
			if decoded, err := base64.StdEncoding.DecodeString(string(raw)); err == nil {
				username = string(decoded)
			}
		}
	}
	if password == "" {
		if raw, ok := secret.Data["password"]; ok {
			if decoded, err := base64.StdEncoding.DecodeString(string(raw)); err == nil {
				password = string(decoded)
			}
		}
	}

	return username, password, nil
}

// patchCertificateRequest updates the owning CertificateRequest with the issued certificate
// and CA chain, setting its Ready condition to True.
func (r *EstOrderReconciler) patchCertificateRequest(ctx context.Context, order *estv1alpha1.EstOrder) error {
	log := logf.FromContext(ctx)

	// Find the owning CertificateRequest by looking at the OwnerReferences
	for _, ref := range order.OwnerReferences {
		if ref.APIVersion == "cert-manager.io/v1" && ref.Kind == "CertificateRequest" {
			certReq := &certmanager.CertificateRequest{}
			if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: order.Namespace}, certReq); err != nil {
				if apierrors.IsNotFound(err) {
					log.V(1).Info("Owning CertificateRequest not found, skipping patch", "name", ref.Name)
					return nil
				}
				return fmt.Errorf("failed to fetch owning CertificateRequest %s: %w", ref.Name, err)
			}

			patchBase := client.MergeFrom(certReq.DeepCopy())

			certReq.Status.Certificate = []byte(order.Status.Certificate)
			if order.Status.CA != "" {
				certReq.Status.CA = []byte(order.Status.CA)
			}

			now := metav1.Now()
			certReq.Status.Conditions = updateCertReqCondition(certReq.Status.Conditions, certmanager.CertificateRequestCondition{
				Type:               certmanager.CertificateRequestConditionReady,
				Status:             cmmeta.ConditionTrue,
				Reason:             certmanager.CertificateRequestReasonIssued,
				Message:            "Certificate issued by EST operator",
				LastTransitionTime: &now,
			})

			if err := r.Status().Patch(ctx, certReq, patchBase); err != nil {
				return fmt.Errorf("failed to patch CertificateRequest status: %w", err)
			}

			log.Info("Patched CertificateRequest with issued certificate", "name", certReq.Name)
			return nil
		}
	}

	log.V(1).Info("No owning CertificateRequest found for EstOrder", "orderName", order.Name)
	return nil
}

func (r *EstOrderReconciler) failOrder(ctx context.Context, order *estv1alpha1.EstOrder, message string, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Error(err, message, "name", order.Name)
	order.Status.Phase = estv1alpha1.PhaseFailed
	order.Status.Message = fmt.Sprintf("%s: %v", message, err)
	if updateErr := r.Status().Update(ctx, order); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EstOrderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&estv1alpha1.EstOrder{}).
		Named("estorder").
		Complete(r)
}