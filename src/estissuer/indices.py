#!/usr/bin/env python3
"""Controller indices."""

import kopf

from estissuer import GROUP
from estissuer.helpers import is_approved, is_est
from estissuer.models.cert_manager_io_v1 import CertificateRequest
from estissuer.models.est_mitre_org_v1alpha1 import EstClusterIssuer, EstIssuer
from estissuer.models.kubernetes_core_v1 import Secret


@kopf.index("estissuers")
def idx_issuers(namespace, name, body, **_):
    """Index of estissuers."""
    issuer = EstIssuer.from_dict(body)
    return {(namespace, name): issuer}


@kopf.index("estclusterissuer")
def idx_clissuers(name, body, **_):
    """Index of estclusterissuers."""
    issuer = EstClusterIssuer.from_dict(body)
    return {name: issuer}


@kopf.index("certificaterequests", when=kopf.all_([is_approved, is_est]))
def idx_enroll(namespace, name, body, **_):
    """Index of approved EST certificaterequests."""
    crs = CertificateRequest.from_dict(body)
    return {(namespace, name): crs}


@kopf.index("secrets", labels={f"{GROUP}/registration": kopf.PRESENT})
def idx_creds(namespace, name, body, **_):
    """Index of RA credentials."""
    secret = Secret.from_dict(body)
    return {(namespace, name): secret}


@kopf.index("secrets", labels={f"{GROUP}/certificate": kopf.PRESENT})
def idx_keys(namespace, name, body, **_):
    """Index of issued certificate private keys for renewals."""
    secret = Secret.from_dict(body)
    return {(namespace, name): secret}
