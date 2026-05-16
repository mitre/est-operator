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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EstOrder Phases
const (
	PhasePending            = "Pending"
	PhaseQueryingAttributes = "QueryingAttributes"
	PhaseEnrolling          = "Enrolling"
	PhaseIssued             = "Issued"
	PhaseRecovery           = "Recovery"
	PhaseFailed             = "Failed"
)

type IssuerRef struct {
	// Name of the EstIssuer
	Name string `json:"name"`

	// Should be EstIssuer or EstClusterIssuer
	// +kubebuilder:validation:Enum=EstIssuer;EstClusterIssuer
	Kind string `json:"kind"`

	// The group name
	// +kubebuilder:validation:Pattern=`est.mitre.org`
	Group string `json:"group"`
}

// EstOrderSpec defines the desired state of EstOrder
type EstOrderSpec struct {
	// EstIssuer that will handle the request
	// +kubebuilder:validation:Required
	IssuerRef IssuerRef `json:"issuerRef"`

	// Certificate Signing Request
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(?:[A-z0-9+/]{4})*(?:[A-z0-9+/]{2}==|[A-z0-9+/]{3}=)?$`
	Request string `json:"request"`

	// Hash of the CSR for adversarial hardening (3.2).
	// +optional
	CSRHash string `json:"csrHash,omitempty"`

	// Renewal flag
	// +kubebuilder:default=false
	Renewal bool `json:"renewal,omitempty"`
}

// EstOrderStatus defines the observed state of EstOrder.
type EstOrderStatus struct {
	// The issued certificate, base64 encoded.
	Certificate string `json:"certificate,omitempty"`

	// The CA chain, base64 encoded.
	CA string `json:"ca,omitempty"`

	// The current state of the order.
	// +kubebuilder:validation:Enum=Pending;QueryingAttributes;Enrolling;Issued;Recovery;Failed
	Phase string `json:"phase,omitempty"`

	// Message describing the current state.
	// +optional
	Message string `json:"message,omitempty"`

	// CSR attributes fetched from the portal.
	// +optional
	Attributes string `json:"attributes,omitempty"`

	// conditions represent the current state of the EstOrder resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EstOrder is the Schema for the estorders API
type EstOrder struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of EstOrder
	// +required
	Spec EstOrderSpec `json:"spec"`

	// status defines the observed state of EstOrder
	// +optional
	Status EstOrderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EstOrderList contains a list of EstOrder
type EstOrderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EstOrder `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EstOrder{}, &EstOrderList{})
}
