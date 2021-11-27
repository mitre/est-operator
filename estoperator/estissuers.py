#!/usr/bin/env python3
"""Handlers for est{cluster}issuers."""

import os
from pathlib import Path

import kopf
import requests.exceptions

from .server import WELLKNOWN
from .utilities import session_factory

INTERVAL = os.environ.get("DEFAULT_INTERVAL", 604800)


@kopf.on.create("est.mitre.org", "estissuers")
@kopf.on.create("est.mitre.org", "estclusterissuers")
@kopf.on.update("est.mitre.org", "estissuers")
@kopf.on.update("est.mitre.org", "estclusterissuers")
@kopf.on.timer("est.mitre.org", "estissuers", interval=INTERVAL)
@kopf.on.timer("est.mitre.org", "estclusterissuers", interval=INTERVAL)
def ready(spec, **_):
    """Update status.ready if spec.cacert is up-to-date."""
    baseUrl = f"https://{spec['host']}:{spec.get('port', 443)}"
    label = Path(spec.get("label", ""))
    url = baseUrl + str(WELLKNOWN / label) + "/cacerts"
    session = session_factory(url, spec["cacert"])
    try:
        response = session.get(url)
    except requests.exceptions.SSLError as err:
        raise kopf.PermanentError("Trust anchor not valid.") from err
    except requests.exceptions.RequestException as err:
        raise kopf.TemporaryError("Error in /cacerts request") from err
    return "Ready"
