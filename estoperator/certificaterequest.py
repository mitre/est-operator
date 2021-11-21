#!/usr/bin/env python3
"""CertificateRequest handlers."""

import base64

import kopf
from kubernetes import client


def request_ready(namespace, name, spec, approved_idx, anchor_idx, **_):
    """Check for request readiness to process."""
    # must be approved
    approved = approved_idx.get((namespace, name))
    # issuer must be ours
    issuer = spec["issuerRef"]
    ours = issuer["kind"] in ["EstIssuer", "EstClusterIssuer"]
    # issuer must exist (in same namespace if EstIssuer)
    space = namespace if issuer["kind"] == "EstIssuer" else None
    exists = anchor_idx.get((space, issuer["name"]))
    return bool(approved and ours and exists)


def cert_ready(namespace, name, orders_owner_idx, orders_certs_idx, **_):
    """Check for certificate readiness."""
    order = orders_owner_idx.get((namespace, name), [None])
    return bool(orders_certs_idx.get(next(o for o in order)))


@kopf.on.create("certificaterequests", when=request_ready)
def ca(namespace, body, spec, anchor_idx: kopf.Index, **_):
    """Update status.ca."""
    issuer = spec["issuerRef"]
    name = issuer["name"]
    space = namespace if issuer["kind"] == "EstIssuer" else None
    anchor = anchor_idx.get((space, name))
    if anchor is None:
        raise kopf.TemporaryError(f"{body['kind']} {name} does not exist.", delay=5)
    # kopf.Store is a concrete Collection; it only implements __len__, __iter__, and __contains__
    return base64.b64encode(next(a for a in anchor).encode("ascii")).decode("ascii")


@kopf.on.create("certificaterequests", when=request_ready)
def create_order(namespace, name, body, spec, approved_idx, anchor_idx, **_):
    """Create EstOrder from CertificateRequest if approved."""
    request = spec["request"]
    resource = {
        "apiVersion": "est.mitre.org/v1alpha1",
        "kind": "EstOrder",
        "metadata": {"name": name},
        "spec": {
            "issuerRef": spec["issuerRef"],
            "request": request,
        },
    }
    kopf.adopt(resource)
    api = client.CustomObjectsApi()
    try:
        _ = api.create_namespaced_custom_object(
            group="est.mitre.org",
            version="v1alpha1",
            namespace=namespace,
            plural="estorders",
            body=resource,
        )
    except client.exceptions.OpenApiException as err:
        raise kopf.TemporaryError(err) from err
    kopf.info(body, reason="Ordered", message=f"Created new EstOrder {name}.")
    # condition = dict(
    #     lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
    #     type="Ready",
    #     status="False",
    #     reason="Pending",
    #     message=message,
    # )
    # if patch.status.get("conditions") is None:
    #     patch.status["conditions"] = []
    # patch.status["conditions"].append(condition)


@kopf.on.create("certificaterequests", when=cert_ready)
def certificate(
    namespace, name, orders_owner_idx: kopf.Index, orders_certs_idx: kopf.Index, **_
):
    """Update status.certificate."""
    order = orders_owner_idx.get((namespace, name), [])
    cert = orders_certs_idx.get(next(o for o in order))
    if cert is None:
        raise kopf.TemporaryError("No EstOrder.")
    return base64.b64encode(next(c for c in cert).encode("ascii")).decode("ascii")
