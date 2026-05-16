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
	"strings"
	"net"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
)

var _ = Describe("EstIssuer Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		estissuer := &estv1alpha1.EstIssuer{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind EstIssuer")
			err := k8sClient.Get(ctx, typeNamespacedName, estissuer)
			if err != nil && errors.IsNotFound(err) {
				estissuer.ObjectMeta = metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: "default",
				}
				Expect(k8sClient.Create(ctx, estissuer)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &estv1alpha1.EstIssuer{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance EstIssuer")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should set NotReady condition when RootPin validation fails", func() {
			By("Starting a mock EST portal")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/cacerts" {
					w.Write([]byte("NOT_A_VALID_CERT")) // Return something that doesn't match the pin
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			By("Creating EstIssuer with a RootPin")
			estissuer.Spec.Host = "localhost"
			estissuer.Spec.Port = 443 // We'll probably need to override this in production, but for test we might use server.Listener.Addr().Port
			estissuer.Spec.RootPin = "EXPECTED_PIN"
			Expect(k8sClient.Update(ctx, estissuer)).To(Succeed())

			// We need a way to tell the controller to use the mock server's address
			// For now, I'll just assume we can pass the host:port through Spec
			estissuer.Spec.Host = "localhost"
			estissuer.Spec.Port = int32(server.Listener.Addr().(*net.TCPAddr).Port)
			Expect(k8sClient.Update(ctx, estissuer)).To(Succeed())

			By("Reconciling the resource")
			controllerReconciler := &EstIssuerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Ready condition is False and the reason is trust anchor mismatch")
			updatedIssuer := &estv1alpha1.EstIssuer{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updatedIssuer)).To(Succeed())
			
			var ready bool
			var pinMismatch bool
			for _, cond := range updatedIssuer.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
					ready = true
				}
				if strings.Contains(cond.Message, "RootPin validation failed") {
					pinMismatch = true
				}
			}
			Expect(ready).To(BeFalse())
			Expect(pinMismatch).To(BeTrue())
		})
	})
})
