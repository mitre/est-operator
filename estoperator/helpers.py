#!/usr/bin/env python

import os
import ssl

import kopf
import kubernetes.client as k8s
import requests

VERSION = "v1alpha1"
GROUP = "est.mitre.org"

WELLKNOWN = "/.well-known/est"

ESTORDER_TEMPLATE = """---
apiVersion: est.mitre.org/v1alpha1
kind: EstOrder
metadata:
  name: "{ordername}"
spec:
  issuerRef:
    name: "{issuername}"
    kind: "{issuerkind}"
    group: "est.mitre.org"
  request: "{request}"
  renewal: {renewal}
"""


class SSLContextAdapter(requests.adapters.HTTPAdapter):
    """Custom SSL adapter with additional restrictions"""

    def init_poolmanager(self, *args, **kwargs):
        """init pool manager with custom SSLContext"""
        context = requests.packages.urllib3.util.ssl_.create_urllib3_context(
            ssl.PROTOCOL_TLSv1_2
        )
        context.verify_mode = ssl.CERT_REQUIRED
        context.options = context.options | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1
        context.check_hostname = True
        return super(SSLContextAdapter, self).init_poolmanager(
            *args, ssl_context=context, **kwargs
        )


def session_factory(base_url, cadata=None):
    """return a requests.Session object with optional client cert and trust anchor"""
    session = requests.Session()
    session.mount(base_url, SSLContextAdapter(cadata=cadata))
    return session


def get_issuer_from_resource(resource):
    """return the named EstIssuer/EstClusterIssuer if Ready"""
    issuer_ref = resource["spec"]["issuerRef"]
    kwargs = dict(
        group=issuer_ref["group"],
        version=VERSION,
        plural=issuer_ref["kind"].lower() + "s",
        name=issuer_ref["name"],
    )
    if kwargs["plural"] == "estissuers":
        kwargs["namespace"] = resource["metadata"]["namespace"]
    try:
        api = k8s.CustomObjectsApi()
        if kwargs.get("namespace"):
            issuer = api.get_namespaced_custom_object(**kwargs)
        else:
            issuer = api.get_cluster_custom_object(**kwargs)
    except k8s.exceptions.OpenApiException as err:
        raise kopf.TemporaryError(eval(err.body)["message"])
    if (
        (issuer.get("status") is None)
        or (issuer["status"].get("estissuer_create") is None)
        or (issuer["status"]["estissuer_create"]["Ready"] != "True")
    ):
        raise kopf.TemporaryError(f"{issuer_ref['name']} not ready")
    kopf.info(
        resource,
        reason="Debugging",
        message=f"get_issuer_from_resource: {issuer['metadata']['name']}",
    )
    return issuer


def get_secret_from_resource(resource):
    """return secret of type tls or basic-auth from secretName or None"""
    secretName = resource["spec"]["secretName"]
    namespace = resource["metadata"].get("namespace")
    if not namespace and resource["kind"] == "EstClusterIssuer":
        namespace = os.getenv("CLUSTER_SCOPE_NAMESPACE", "est-operator")
    try:
        api = k8s.CoreV1Api()
        secret = api.read_namespaced_secret(secretName, namespace)
    except k8s.exceptions.OpenApiException:
        secret = None
    if secret and secret.type not in ["kubernetes.io/basic-auth", "kubernetes.io/tls"]:
        secret = None
    kopf.info(
        resource,
        reason="Debugging",
        message=f"get_secret_from_resource: {namespace}:{secretName} {secret is not None}",
    )
    return secret


def get_owner_by_kind(resource, kind_list):
    """get the first owner of any kind in kind_list from resource, if present"""
    ownerReferences = resource["metadata"].get("ownerReferences", [])
    (owner,) = [owner for owner in ownerReferences if owner["kind"] in kind_list]
    if not owner:
        kopf.info(
            resource,
            reason="Debugging",
            message=f"get_owner_by_kind: {kind_list} not found",
        )
        return None
    group, version = owner["apiVersion"].split("/")
    namespace = resource["metadata"]["namespace"]
    kwargs = dict(
        group=group,
        version=version,
        plural=owner["kind"].lower() + "s",
        name=owner["name"],
    )
    try:
        api = k8s.CustomObjectsApi()
        # ownerRefs don't have namespace attributes, so we have to try both.
        # Most resources are namespaced, so do that first. Namespaced owners
        # have to be in the same namespace.
        try:
            owner = api.get_namespaced_custom_object(namespace=namespace, **kwargs)
        except k8s.exceptions.OpenApiException:
            owner = api.get_cluster_custom_object(**kwargs)
    except k8s.exceptions.OpenApiException as err:
        raise kopf.TemporaryError(eval(err.body)["message"])
    kopf.info(resource, reason="Debugging", message=f"get_owner_by_kind: {kwargs}")
    return owner
