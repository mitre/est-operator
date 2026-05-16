/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

// EstIssuerReconciler reconciles a EstIssuer object
type EstIssuerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=est.mitre.org,resources=estissuers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *EstIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	estissuer := &estv1alpha1.EstIssuer{}
	if err := r.Get(ctx, req.NamespacedName, estissuer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Perform connectivity check
	address := fmt.Sprintf("%s:%d", estissuer.Spec.Host, estissuer.Spec.Port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	
	var ready bool
	var message string

	if err != nil {
		log.Error(err, "Connectivity check failed", "address", address)
		ready = false
		message = fmt.Sprintf("Connectivity check failed: %v", err)
	} else {
		conn.Close()
		log.Info("Connectivity check succeeded", "address", address)
		
		// If RootPin is specified, perform TA validation
		if estissuer.Spec.RootPin != "" {
			if err := r.validateRootPin(ctx, estissuer); err != nil {
				log.Error(err, "RootPin validation failed", "address", address)
				ready = false
				message = "RootPin validation failed"
			} else {
				ready = true
				message = "EST portal is reachable and root pin validated"
			}
		} else {
			ready = true
			message = "EST portal is reachable"
		}
	}

	// Update status conditions
	if err := r.updateStatus(ctx, estissuer, ready, message); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *EstIssuerReconciler) validateRootPin(ctx context.Context, estissuer *estv1alpha1.EstIssuer) error {
	url := fmt.Sprintf("http://%s:%d/cacerts", estissuer.Spec.Host, estissuer.Spec.Port)
	
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

	if actualPin != estissuer.Spec.RootPin {
		return fmt.Errorf("calculated pin %s does not match expected pin %s", actualPin, estissuer.Spec.RootPin)
	}

	return nil
}

func (r *EstIssuerReconciler) updateStatus(ctx context.Context, estissuer *estv1alpha1.EstIssuer, ready bool, message string) error {
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ConnectivityCheck",
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}

	if ready {
		condition.Status = metav1.ConditionTrue
	}

	estissuer.Status.Conditions = []metav1.Condition{condition}
	return r.Status().Update(ctx, estissuer)
}

// SetupWithManager sets up the controller with the Manager.
func (r *EstIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&estv1alpha1.EstIssuer{}).
		Named("estissuer").
		Complete(r)
}
