package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
)

// IssuerStatus represents the result of a connectivity check and optional RootPin validation.
type IssuerStatus struct {
	Ready   bool
	Message string
}

// checkIssuerConnectivity performs a TCP connectivity check and optional RootPin validation
// against an EST issuer's host:port. This is shared logic used by both EstIssuer and EstClusterIssuer.
func checkIssuerConnectivity(ctx context.Context, host string, port int32, rootPin string) IssuerStatus {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)

	if err != nil {
		return IssuerStatus{
			Ready:   false,
			Message: fmt.Sprintf("Connectivity check failed: %v", err),
		}
	}
	conn.Close()

	logf.FromContext(ctx).Info("Connectivity check succeeded", "address", address)

	if rootPin != "" {
		if err := validateRootPin(ctx, host, port, rootPin); err != nil {
			return IssuerStatus{
				Ready:   false,
				Message: fmt.Sprintf("RootPin validation failed: %v", err),
			}
		}
		return IssuerStatus{
			Ready:   true,
			Message: "EST portal is reachable and root pin validated",
		}
	}

	return IssuerStatus{
		Ready:   true,
		Message: "EST portal is reachable",
	}
}

// validateRootPin fetches /cacerts from the EST portal and verifies the response hash
// against the provided root pin (SHA-256 of the response body).
func validateRootPin(ctx context.Context, host string, port int32, expectedPin string) error {
	url := fmt.Sprintf("http://%s:%d/cacerts", host, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch /cacerts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from /cacerts: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read /cacerts response: %w", err)
	}

	hash := sha256.Sum256(body)
	actualPin := hex.EncodeToString(hash[:])

	if actualPin != expectedPin {
		return fmt.Errorf("calculated pin %s does not match expected pin %s", actualPin, expectedPin)
	}

	return nil
}

// updateIssuerStatus is a generic status updater for both EstIssuer and EstClusterIssuer.
func updateIssuerStatus(ctx context.Context, obj client.Object, scheme *runtime.Scheme, status IssuerStatus) error {
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ConnectivityCheck",
		Message:            status.Message,
		LastTransitionTime:  metav1.Now(),
	}

	if status.Ready {
		condition.Status = metav1.ConditionTrue
	}

	switch v := obj.(type) {
	case *estv1alpha1.EstIssuer:
		v.Status.Conditions = []metav1.Condition{condition}
	case *estv1alpha1.EstClusterIssuer:
		v.Status.Conditions = []metav1.Condition{condition}
	default:
		return fmt.Errorf("unsupported issuer type: %T", obj)
	}

	return ctrl.SetControllerReference(obj, obj, scheme) // Needed to ensure GVK is set before status update
}

// EstIssuerReconciler reconciles a EstIssuer object
type EstIssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers/finalizers,verbs=update

func (r *EstIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	estissuer := &estv1alpha1.EstIssuer{}
	if err := r.Get(ctx, req.NamespacedName, estissuer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	status := checkIssuerConnectivity(ctx, estissuer.Spec.Host, estissuer.Spec.Port, estissuer.Spec.RootPin)
	if !status.Ready {
		log.Error(fmt.Errorf("%s", status.Message), "Issuer not ready")
	} else {
		log.Info("Issuer is ready", "message", status.Message)
	}

	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ConnectivityCheck",
		Message:            status.Message,
		LastTransitionTime:  metav1.Now(),
	}
	if status.Ready {
		condition.Status = metav1.ConditionTrue
	}

	estissuer.Status.Conditions = []metav1.Condition{condition}
	if err := r.Status().Update(ctx, estissuer); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EstIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&estv1alpha1.EstIssuer{}).
		Named("estissuer").
		Complete(r)
}

// EstClusterIssuerReconciler reconciles a EstClusterIssuer object
type EstClusterIssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=est.mitre.org,resources=estclusterissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=est.mitre.org,resources=estclusterissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=est.mitre.org,resources=estclusterissuers/finalizers,verbs=update

func (r *EstClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	clusterIssuer := &estv1alpha1.EstClusterIssuer{}
	if err := r.Get(ctx, req.NamespacedName, clusterIssuer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	status := checkIssuerConnectivity(ctx, clusterIssuer.Spec.Host, clusterIssuer.Spec.Port, clusterIssuer.Spec.RootPin)
	if !status.Ready {
		log.Error(fmt.Errorf("%s", status.Message), "ClusterIssuer not ready")
	} else {
		log.Info("ClusterIssuer is ready", "message", status.Message)
	}

	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ConnectivityCheck",
		Message:            status.Message,
		LastTransitionTime:  metav1.Now(),
	}
	if status.Ready {
		condition.Status = metav1.ConditionTrue
	}

	clusterIssuer.Status.Conditions = []metav1.Condition{condition}
	if err := r.Status().Update(ctx, clusterIssuer); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EstClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&estv1alpha1.EstClusterIssuer{}).
		Named("estclusterissuer").
		Complete(r)
}