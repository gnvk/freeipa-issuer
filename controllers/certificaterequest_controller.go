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

package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "freeipa-issuer/api/v1alpha1"
	"freeipa-issuer/freeipa"

	cmapiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// CertificateRequestReconciler reconciles a CertificateRequest object
type CertificateRequestReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=certificaterequests/status,verbs=get;update;patch

func (r *CertificateRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled
	cr := &cmapi.CertificateRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, cr); err != nil {
		log.Error(err, "failed to retrieve CertificateRequest resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check the CertificateRequest's issuerRef and if it does not match the api
	// group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != "" && cr.Spec.IssuerRef.Group != api.GroupVersion.Group {
		log.V(4).Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// If the certificate data is already set then we skip this request as it
	// has already been completed in the past.
	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}

	// Fetch the Issuer resource
	issuer := api.FreeIpaIssuer{}
	issuerNamespaceName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      cr.Spec.IssuerRef.Name,
	}
	if err := r.Client.Get(ctx, issuerNamespaceName, &issuer); err != nil {
		log.Error(err, "failed to retrieve FreeIpa issuer resource", "namespace", req.Namespace, "name", cr.Spec.IssuerRef.Name)
		return ctrl.Result{}, err
	}

	// Fetch the auth secret
	var secret corev1.Secret
	secretNamespaceName := types.NamespacedName{
		Namespace: req.Namespace,
		Name:      issuer.Spec.Auth.UserPass.SecretRef.Name,
	}
	if err := r.Client.Get(ctx, secretNamespaceName, &secret); err != nil {
		log.Error(err, "failed to retrieve FreeIpa issuer secret", "namespace",
			secretNamespaceName.Namespace, "name", secretNamespaceName.Name)
		r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed,
			"Failed to retrieve issuer secret: %v", err)
		return ctrl.Result{}, err
	}

	username, ok := secret.Data["username"]
	if !ok {
		err := fmt.Errorf("secret %s does not contain key 'username'", secret.Name)
		log.Error(err, "failed to retrieve FreeIpa issuer secret", "namespace",
			secretNamespaceName.Namespace, "name", secretNamespaceName.Name)
		r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed,
			"Failed to retrieve issuer secret: %v", err)
		return ctrl.Result{}, err
	}

	password, ok := secret.Data["password"]
	if !ok {
		err := fmt.Errorf("secret %s does not contain key 'password'", secret.Name)
		log.Error(err, "failed to retrieve FreeIpa issuer secret", "namespace",
			secretNamespaceName.Namespace, "name", secretNamespaceName.Name)
		r.setStatus(ctx, cr, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed,
			"Failed to retrieve issuer secret: %v", err)
		return ctrl.Result{}, err
	}

	ipaServer := freeipa.IpaServer{
		Host:     issuer.Spec.Host,
		Realm:    issuer.Spec.Realm,
		Username: string(username),
		Password: string(password),
	}
	signedPEM, trustedCAs, err := freeipa.Sign(cr, &ipaServer)
	if err != nil {
		log.Error(err, "failed to sign certificate request")
		return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionFalse,
			cmapi.CertificateRequestReasonFailed, "Failed to sign certificate request: %v", err)
	}

	cr.Status.Certificate = signedPEM
	cr.Status.CA = trustedCAs

	return ctrl.Result{}, r.setStatus(ctx, cr, cmmeta.ConditionTrue,
		cmapi.CertificateRequestReasonIssued, "Certificate issued")
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string, args ...interface{}) error {
	completeMessage := fmt.Sprintf(message, args...)
	cmapiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	eventType := corev1.EventTypeNormal
	if status == cmmeta.ConditionFalse {
		eventType = corev1.EventTypeWarning
	}
	r.Recorder.Event(cr, eventType, reason, completeMessage)

	return r.Client.Status().Update(ctx, cr)
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
