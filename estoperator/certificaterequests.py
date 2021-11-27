#!/usr/bin/env python3
"""Handlers for certificaterequests."""

import base64
from datetime import datetime
from tempfile import NamedTemporaryFile

import kopf

from .callbacks import is_approved, is_est, is_initial
from .utilities import get_issuer, get_secret, post_pkcs10_request, session_factory


@kopf.on.create(
    "cert-manager.io",
    "certificaterequests",
    when=kopf.all_([is_est, is_approved, is_initial]),
)
def ca(namespace, spec, issuer_idx, **_):
    """Update status.ca."""
    issuer = get_issuer(namespace, spec["issuerRef"], issuer_idx)
    return issuer["ca"]


@kopf.on.create(
    "cert-manager.io",
    "certificaterequests",
    field="status.certificate",
    value=kopf.ABSENT,
    when=kopf.all_([is_est, is_approved]),
)
def conditions(status, patch, **_):
    """Update certificaterequests with Ready=Pending status."""
    conditions = status.get("conditions", [])
    others = [cond for cond in conditions if cond["type"] != "Ready"]
    condition = dict(
        lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
        type="Ready",
        status="False",
        reason="Pending",
        message="EstIssuer certificate pending.",
    )
    # use patch b/c results delivery causes an error
    patch.status["conditions"] = others + [condition]


@kopf.on.create(
    "cert-manager.io",
    "certificaterequests",
    field="status.certificate",
    value=kopf.ABSENT,
    when=kopf.all_([is_est, is_approved, is_initial]),
)
def certificate(namespace, annotations, spec, status, patch, issuer_idx, **_):
    """Handle initial enrollment."""
    issuer = get_issuer(namespace, spec["issuerRef"], issuer_idx)
    request = base64.b64decode(spec["request"])
    kwargs = {
        "auth": (
            base64.b64decode(issuer["cred"]["username"]).decode(),
            base64.b64decode(issuer["cred"]["password"]).decode(),
        )
    }
    certs = post_pkcs10_request(
        issuer["url"] + "/simpleenroll", issuer["pem"], request, **kwargs
    )
    conditions = status.get("conditions", [])
    others = [cond for cond in conditions if cond["type"] != "Ready"]
    condition = dict(
        lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
        type="Ready",
        status="True",
        reason="Issued",
        message="Certificate issued.",
    )
    # use patch b/c results delivery causes an error
    patch.status["conditions"] = others + [condition]
    patch.status["certificate"] = base64.b64encode(
        "".join(certs).encode("ascii")
    ).decode("ascii")


@kopf.on.create(
    "cert-manager.io",
    "certificaterequests",
    field="status.certificate",
    value=kopf.ABSENT,
    when=kopf.all_([is_est, is_approved, kopf.not_(is_initial)]),
)
def certificate(namespace, annotations, spec, status, patch, issuer_idx, **_):
    """Handle certificate renewal (basic auth)."""
    # TODO: Change this to client cert authN.
    # get Cert from annotation cert-manager.io/certificate-name
    # get secret from where
    # write secret to tempfiles
    # set kwargs["cert"] = (certfile, keyfile)
    issuer = get_issuer(namespace, spec["issuerRef"], issuer_idx)
    request = base64.b64decode(spec["request"])
    kwargs = {
        "auth": (
            base64.b64decode(issuer["cred"]["username"]).decode(),
            base64.b64decode(issuer["cred"]["password"]).decode(),
        )
    }
    certs = post_pkcs10_request(
        issuer["url"] + "/simplereenroll", issuer["pem"], request, **kwargs
    )
    conditions = status.get("conditions", [])
    others = [cond for cond in conditions if cond["type"] != "Ready"]
    condition = dict(
        lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
        type="Ready",
        status="True",
        reason="Issued",
        message="Certificate issued.",
    )
    # use patch b/c results delivery causes an error
    patch.status["conditions"] = others + [condition]
    patch.status["certificate"] = base64.b64encode(
        "".join(certs).encode("ascii")
    ).decode("ascii")
