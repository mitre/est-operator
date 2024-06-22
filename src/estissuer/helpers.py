#!/usr/bin/env python3
"""Helper methods."""

from estissuer import GROUP
from estissuer.models.cert_manager_io_v1 import (
    CertificateRequestSpec,
    CertificateRequestStatus,
)


def is_est(spec, **_):
    """Returns TRUE is issuerRef.group is the EST issuer group."""
    crspec = CertificateRequestSpec.from_dict(spec)
    assert crspec.issuer_ref is not None
    return crspec.issuer_ref.group == GROUP


def is_cluster(spec, **_):
    """Returns TRUE if issuerRef.kind is EstClusterIssuer."""
    crspec = CertificateRequestSpec.from_dict(spec)
    assert crspec.issuer_ref is not None
    return crspec.issuer_ref.kind == "EstClusterIssuer"


def is_namespaced(spec, **_):
    """Returns TRUE id issuerRef.kind is EstIssuer."""
    crspec = CertificateRequestSpec.from_dict(spec)
    assert crspec.issuer_ref is not None
    return crspec.issuer_ref.kind == "EstIssuer"


def is_approved(status, **_):
    """Return TRUE if STATUS contains Condition of type Approved."""
    crs_status = CertificateRequestStatus.from_dict(status)
    return "Approved" in [
        condition.type for condition in crs_status.conditions
    ]


def is_initial(annotations, **_):
    """Return TRUE if ANNOTATIONS contains 'cert-manager.io/certificate-revision' == 1."""
    revision = int(annotations.get("cert-manager.io/certificate-revision", 1))
    return revision == 1
