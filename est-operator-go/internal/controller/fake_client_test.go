package controller

import (
	"context"
	"testing"

	estv1alpha1 "git.mitre.org/est-operator/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sclientscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFakeClientBasic(t *testing.T) {
	s := runtime.NewScheme()
	_ = k8sclientscheme.AddToScheme(s)
	estv1alpha1.AddToScheme(s)

	ctx := context.Background()
	order := &estv1alpha1.EstOrder{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().WithScheme(s).Build()
	err := client.Create(ctx, order)
	assert.NoError(t, err)

	found := &estv1alpha1.EstOrder{}
	err = client.Get(ctx, types.NamespacedName{Name: "test", Namespace: "default"}, found)
	assert.NoError(t, err)
	assert.Equal(t, "test", found.Name)
}
