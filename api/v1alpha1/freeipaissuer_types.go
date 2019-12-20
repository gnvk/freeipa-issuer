/*

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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FreeIpaIssuerSpec defines the desired state of FreeIpaIssuer
type FreeIpaIssuerSpec struct {
	// URL is the base URL for the FreeIPA instance.
	URL string `json:"foo,omitempty"`

	// CABundle is a base64 encoded TLS certificate used to verify connections
	// to the FreeIpa server. If not set the system root certificates
	// are used to validate the TLS connection.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	Auth FreeIpaAuthSpec `json:"auth"`
}

type FreeIpaAuthSpec struct {
	UserPass FreeIpaUserPassAuthSpec `json:"userPass"`
}

type FreeIpaUserPassAuthSpec struct {
	SecretRef *v1.LocalObjectReference `json:"secretRef"`
}

// FreeIpaIssuerStatus defines the observed state of FreeIpaIssuer
type FreeIpaIssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true

// FreeIpaIssuer is the Schema for the freeipaissuers API
type FreeIpaIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FreeIpaIssuerSpec   `json:"spec,omitempty"`
	Status FreeIpaIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FreeIpaIssuerList contains a list of FreeIpaIssuer
type FreeIpaIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FreeIpaIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FreeIpaIssuer{}, &FreeIpaIssuerList{})
}
