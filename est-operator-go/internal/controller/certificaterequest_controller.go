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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
)

const estGroup = "est.mitre.org"

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=est.mitre.org,resources=estorders,verbs=create;get;list;watch;patch;update

// CertificateRequestReconciler handles CertificateRequest resources and triggers EstOrder creation.
type CertificateRequestReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var certReq certmanager.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certReq); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Filter: only handle requests referencing our group
	if certReq.Spec.IssuerRef.Group != estGroup {
		log.V(1).Info("Skipping CertificateRequest: issuerRef.group is not est.mitre.org", "group", certReq.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Skip if already Ready (either issued or failed)
	for _, cond := range certReq.Status.Conditions {
		if cond.Type == certmanager.CertificateRequestConditionReady {
			if cond.Status == cmmeta.ConditionTrue {
				log.V(1).Info("CertificateRequest already Ready, skipping", "name", certReq.Name)
				return ctrl.Result{}, nil
			}
			// If the condition reason is Denied, skip entirely
			if cond.Reason == certmanager.CertificateRequestReasonDenied {
				log.V(1).Info("CertificateRequest is denied, skipping", "name", certReq.Name)
				return ctrl.Result{}, nil
			}
		}
	}

	// Check if we already have an EstOrder for this CertificateRequest
	orderName := certReq.Name + "-order"
	existingOrder := &estv1alpha1.EstOrder{}
	err := r.Get(ctx, types.NamespacedName{Name: orderName, Namespace: certReq.Namespace}, existingOrder)
	if err == nil {
		// EstOrder already exists, nothing to do
		log.V(1).Info("EstOrder already exists", "name", orderName)
		return ctrl.Result{}, nil
	}
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// Create the EstOrder
	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      orderName,
			Namespace: certReq.Namespace,
		},
		Spec: estv1alpha1.EstOrderSpec{
			IssuerRef: estv1alpha1.IssuerRef{
				Name:  certReq.Spec.IssuerRef.Name,
				Kind:  certReq.Spec.IssuerRef.Kind,
				Group: certReq.Spec.IssuerRef.Group,
			},
			Request: string(certReq.Spec.Request),
		},
	}

	// Set CertificateRequest as owner of the EstOrder
	if err := ctrl.SetControllerReference(&certReq, order, r.Scheme); err != nil {
		log.Error(err, "Failed to set controller reference on EstOrder")
		return ctrl.Result{}, err
	}

	if err := r.Create(ctx, order); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.V(1).Info("EstOrder already exists (race condition)", "name", orderName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to create EstOrder: %w", err)
	}

	log.Info("Created EstOrder for CertificateRequest", "orderName", orderName, "certReqName", certReq.Name)

	// Update CertificateRequest status to Pending
	patchCtx := ctx
	patchBase := client.MergeFrom(certReq.DeepCopy())
	now := metav1.Now()
	certReq.Status.Conditions = updateCertReqCondition(certReq.Status.Conditions, certmanager.CertificateRequestCondition{
		Type:               certmanager.CertificateRequestConditionReady,
		Status:             cmmeta.ConditionFalse,
		Reason:             certmanager.CertificateRequestReasonPending,
		Message:            "Created EstOrder " + orderName,
		LastTransitionTime: &now,
	})

	if err := r.Status().Patch(patchCtx, &certReq, patchBase); err != nil {
		log.Error(err, "Failed to patch CertificateRequest status", "name", certReq.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// updateCertReqCondition replaces or appends a condition of the same type.
func updateCertReqCondition(conditions []certmanager.CertificateRequestCondition, newCond certmanager.CertificateRequestCondition) []certmanager.CertificateRequestCondition {
	for i, c := range conditions {
		if c.Type == newCond.Type {
			conditions[i] = newCond
			return conditions
		}
	}
	return append(conditions, newCond)
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanager.CertificateRequest{}).
		Named("certificaterequest").
		Complete(r)
}