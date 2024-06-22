#!/usr/bin/env python3
"""CertificateRequest controller."""
import kopf

from estissuer.helpers import is_approved, is_cluster, is_est, is_namespaced
from estissuer.indices import idx_clissuers
from estissuer.models.cert_manager_io_v1 import CertificateRequestSpec


@kopf.on.create(
    "certificaterequests",
    when=kopf.all_([is_approved, is_est, is_namespaced]),
    param=True,
)
@kopf.on.create(
    "certificaterequests",
    when=kopf.all_([is_approved, is_est, is_cluster]),
    param=False,
)
def ca(namespace, name, spec, idx_issuer: kopf.Index, param, **_):
    """Returns CA cert for selected issuer."""
    crs = CertificateRequestSpec.from_dict(spec)
    if param:
        issuer = idx_issuer.get((namespace, crs.issuer_ref.name))
    else:
        issuer = idx_clissuers.get(crs.issuer_ref.name)
    if not issuer:
        raise kopf.TemporaryError(
            f"No such EST issuer: {namespace}/{crs.issuer_ref.kind}/{crs.issuer_ref.name}."
        )
    return issuer.spec.cacert


# enrollment:
# - if annotation:cert-manager.io/certificate-revision='1', call simpleenroll()
# - otherwise, call simplereenroll()
#
