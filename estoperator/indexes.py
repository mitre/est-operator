#!/usr/bin/env python3
"""Controller indexes."""

import base64
import os
from pathlib import Path

import kopf
from kubernetes import client

from .server import WELLKNOWN


@kopf.index("secrets", annotations={"cert-manager.io/issuer-group": "est.mitre.org"})
def secrets_idx(namespace, name, annotations, **_):
    """Index TLS secret references by certificate name."""
    certificate = annotations["cert-manager.io/certificate-name"]
    return {(namespace, certificate): name}


@kopf.index("estissuers")
@kopf.index(
    "estclusterissuers", param=os.environ.get("DEFAULT_NAMESPACE", "est-operator")
)
def issuer_idx(namespace, name, spec, param, **_):
    """Issuers index.

    This index caches secret data. PARAM is the default namespace for
    EstClusterIssuer credentials.

    """
    ca = base64.b64encode(spec["cacert"].encode("ascii")).decode("ascii")
    secret_ns = param if param else namespace
    secret_name = spec["secretRef"]["name"]
    api = client.CoreV1Api()
    baseUrl = f"https://{spec['host']}:{spec.get('port', 443)}"
    label = Path(spec.get("label", ""))
    try:
        secret = api.read_namespaced_secret(secret_name, secret_ns)
    except client.OpenApiException as err:
        raise kopf.TemporaryError(err) from err
    return {
        (namespace, name): {
            "ca": ca,
            "pem": spec["cacert"],
            "cred": secret.data,
            "url": baseUrl + str(WELLKNOWN / label),
        }
    }
