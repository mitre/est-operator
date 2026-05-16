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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EstClusterIssuerSpec defines the desired state of EstClusterIssuer
type EstClusterIssuerSpec struct {
	// EST portal hostname
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// EST portal port
	// +kubebuilder:default=443
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// EST portal path under the well-known EST endpoint. See RFC 7030 Sec 3.2.2.
	// Multiple labels can be specified with a '/' separator, forming a URL path.
	// +kubebuilder:default=""
	Label string `json:"label,omitempty"`

	// EST portal root certificate, PEM encoded, and base64 encoded.
	// This certificate is used to authenticate the portal, and is
	// the Explicit Trust Anchor as defined in RFC 7030 Sec 1.1.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`
	CAcert string `json:"cacert"`

	// Name of a Secret with the EST portal credential. Secret must be type kubernetes.io/basic-auth.
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// EstClusterIssuerStatus defines the observed state of EstClusterIssuer.
type EstClusterIssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the EstClusterIssuer resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EstClusterIssuer is the Schema for the estclusterissuers API
type EstClusterIssuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of EstClusterIssuer
	// +required
	Spec EstClusterIssuerSpec `json:"spec"`

	// status defines the observed state of EstClusterIssuer
	// +optional
	Status EstClusterIssuerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// EstClusterIssuerList contains a list of EstClusterIssuer
type EstClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []EstClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EstClusterIssuer{}, &EstClusterIssuerList{})
}
