#!/usr/bin/env python3
"""Indexes used by handlers."""

import kopf
from kubernetes import client


@kopf.index("estissuers")
@kopf.index("estclusterissuers")
def anchor_idx(namespace, name, spec, **_):
    """Index of namespaced issuer trust anchors."""
    return {(namespace, name): spec.get("cacert")}


@kopf.index("estissuers")
@kopf.index("estclusterissuers", param="cert-manager")
def issuers_idx(namespace, name, spec, param, **_):
    """Index of issuer credentials.

    This index caches actual secrets. param provides the default namespace for
    cluster issuers.

    """
    space = param if param else namespace
    secret_name = spec["secretRef"]["name"]
    api = client.CoreV1Api()
    try:
        secret = api.read_namespaced_secret(secret_name, space)
    except client.OpenApiException as err:
        raise kopf.TemporaryError(err) from err
    return {(space, name): secret.data}


@kopf.index("estorders")
def orders_owner_idx(namespace, name, meta, **_):
    """Index of estorders by owner."""
    owner = meta.get("ownerReferences")[0]
    return {(namespace, owner.get("name")): (namespace, name)}


@kopf.index("estorders")
def orders_certs_idx(namespace, name, status, field="status.certificate", **_):
    """Index of estorder certificates by order."""
    return {(namespace, name): status.get("certificate")}


@kopf.index("certificaterequests", field="spec.issuerRef.group", value="est.mitre.org")
def approved_idx(namespace, name, status, **_):
    """Index of approved CertificateRequests."""
    conditions = status.get("conditions", [])
    approved = [cond["status"] for cond in conditions if cond["type"] == "Approved"]
    if "True" not in approved:
        raise kopf.TemporaryError(
            f"CertificateRequest ({namespace}, {name}) not approved."
        )
    return {(namespace, name): True}


@kopf.index("certificates", field="status.renewalTime")
def renewal_idx(namespace, name, spec, **_):
    """Index of certificate renewal secrets."""
    issuer = spec["issuerRef"]
    secret_name = spec["secretName"]
    api = client.CoreV1Api()
    try:
        secret = api.read_namespaced_secret(secret_name, namespace)
    except client.OpenApiException as err:
        raise kopf.TemporaryError(err) from err
    return {(namespace, name): secret.data}