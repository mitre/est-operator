#!/usr/bin/env python3
"""Callbacks for handlers."""


def is_est(spec, **_):
    """Return TRUE if spec.issuerRef.group is est.mitre.org."""
    group = spec["issuerRef"]["group"] == "est.mitre.org"
    kind = spec["issuerRef"]["kind"] in ["EstIssuer", "EstClusterIssuer"]
    return group and kind


def is_approved(status, **_):
    """Return TRUE if status.conditions includes Approved status."""
    conditions = [
        cond for cond in status.get("conditions", []) if cond["type"] == "Approved"
    ]
    return bool(conditions)


def is_initial(annotations, **_):
    """Return TRUE if certificate revision annotation is '1'."""
    revision = annotations.get("cert-manager.io/certificate-revision", "1")
    return revision == "1"
