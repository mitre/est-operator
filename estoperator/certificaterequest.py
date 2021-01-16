#!/usr/bin/env python

from datetime import datetime

import kopf
import kubernetes.client as k8s
import yaml

from estoperator.helpers import (ESTORDER_TEMPLATE, GROUP, VERSION,
                                 get_issuer_from_resource, get_owner_by_kind,
                                 get_secret_from_resource)


def is_our_certrequest(spec, **_):
    """filter CertificateRequest resources for our group"""
    issuer = spec.get("issuerRef")
    return (issuer is not None) and (issuer.get("group") == GROUP)


@kopf.on.create("cert-manager.io", "v1", "certificaterequests", when=is_our_certrequest)
def estissuer_certrequest_handler(namespace, spec, meta, body, patch, **_):
    """reconcile CertificateRequests"""
    # gather resources
    issuer = get_issuer_from_resource(body)
    cert = get_owner_by_kind(body, ["Certificate"])
    cert_secret = get_secret_from_resource(cert)
    # Create an EstOrder for it in request namespace
    renewal = (
        False if cert_secret is None else (cert_secret.type == "kubernetes.io/tls")
    )
    resource = ESTORDER_TEMPLATE.format(
        ordername=meta["name"] + "-order",
        issuername=issuer["metadata"]["name"],
        issuerkind=issuer["kind"],
        request=spec["request"],
        renewal=renewal,
    )
    resource = yaml.safe_load(resource)
    # Set EstOrder owner to CertificateRequest
    kopf.adopt(resource)
    # create the resource
    try:
        api = k8s.CustomObjectsApi()
        _ = api.create_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural="estorders",
            body=resource,
        )
    except k8s.exceptions.OpenApiException as err:
        raise kopf.TemporaryError(eval(err.body)["message"]) from err
    # log event
    message = f"Created new EstOrder {resource['metadata']['name']}"
    kopf.info(
        body,
        reason="Ordered",
        message=message,
    )
    # set certificate request status to False,Pending
    # utcnow()+"Z" b/c python datetime doesn't do Zulu
    # timepec='seconds' b/c cert-manager webhook will trim to seconds
    # (causing the API to warn about the inconsistency)
    condition = dict(
        lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
        type="Ready",
        status="False",
        reason="Pending",
        message=message,
    )
    if patch.status.get("conditions") is None:
        patch.status["conditions"] = []
    patch.status["conditions"].append(condition)
