#!/usr/bin/env python3
"""General methods and callbacks.."""

import base64
import ssl
from datetime import datetime, timezone

import kopf
import requests
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from dateutil.parser import parse
from kubernetes import client


class SSLContextAdapter(requests.adapters.HTTPAdapter):
    """Custom SSL adapter with in-memory trust anchors and security restrictions."""

    def __init__(self, *args, cadata=None, **kwargs):
        """Initialize with CADATA in-memory trust anchor."""
        self.cadata = cadata
        super(SSLContextAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom SSLContext."""
        context = ssl.create_default_context(cadata=self.cadata)
        context.verify_mode = ssl.CERT_REQUIRED
        context.options = context.options | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1
        context.check_hostname = True
        return super(SSLContextAdapter, self).init_poolmanager(
            *args, ssl_context=context, **kwargs
        )


def session_factory(url, cert):
    """Create requests.Session for URL with SSLContext that trusts CERT."""
    session = requests.Session()
    session.mount(url, SSLContextAdapter(cadata=cert))
    return session


def post_pkcs10_request(url, cert, data, **kwargs):
    """Post PKCS#10 DATA to URL trusting CERT.

    Returns a list of PEM encoded certificates, or raises a TemporaryError. Must
    provide `auth` or `cert` in `kwargs` for client authentication.

    """
    session = session_factory(url, cert)
    try:
        response = session.post(
            url,
            data=data,
            headers={
                "Content-Type": "application/pkcs10",
                "Content-Transfer-Encoding": "base64",
            },
            **kwargs,
        )
    except (requests.exceptions.SSLError, requests.RequestException) as err:
        raise kopf.TemporaryError(err)
    if response.status_code not in [200, 202]:
        raise kopf.TemporaryError(
            f"{response.status_code} {response.reason} {response.content}", delay=600
        )
    if response.status_code == 202:
        # 202 status means the CSR is accepted but not yet signed (e.g., needs
        # RA approval). RFC 7030 says to submit the same CSR after a delay
        # optionally supplied by the Retry-After header. The resubmitted CSR is
        # needed for the server to match the request at the server.
        after = response.headers.get("Retry-After", 600)
        if isinstance(after, str):
            if after.isnumeric():
                after = int(after)
            else:
                after = parse(after)
                after = after - datetime.now(timezone.utc)
                after = after.seconds
        raise kopf.TemporaryError("Reqest accepted pending issuance", delay=after)
    certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(response.content))
    certs = [cert.public_bytes(Encoding.PEM).decode("ascii") for cert in certs]
    return certs


def get_issuer(namespace, issuer_ref, issuer_idx):
    """Return issuer data from the index."""
    name = issuer_ref["name"]
    space = namespace if issuer_ref["kind"] == "EstIssuer" else None
    issuer = next(item for item in issuer_idx.get((space, name), [None]))
    if issuer is None:
        raise kopf.TemporaryError(f"No such issuer {issuer_ref} in {space} namespace.")
    return issuer


def get_secret(namespace, annotations, secrets_idx):
    """Retrieve secret for reenrollment."""
    name = annotations.get("cert-manager.io/certificate-name")
    secret_name = next(item for item in secrets_idx.get((namespace, name), [None]))
    if secret_name is None:
        raise kopf.TemporaryError(f"Secret {secret_name} not found.")
    try:
        api = client.CoreV1Api()
        secret = api.read_namespaced_secret(secret_name, namespace)
    except client.OpenApiException as err:
        raise kopf.TemporaryError() from err
    return secret
