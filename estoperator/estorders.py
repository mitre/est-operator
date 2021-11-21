#!/usr/bin/env python3
"""Handlers for estorders."""

import kopf


@kopf.on.create("estorders", labels={"est.mitre.org/mode": "initial"})
def simpleenroll(**_):
    """Submit CSR to issuer with RA credential."""


@kopf.on.create("estorders", labels={"est.mitre.org/mode": "renewal"})
def simplereenroll(**_):
    """Submit CSR to issuer with cert authentication."""
