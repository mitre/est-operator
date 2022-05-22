#!/usr/bin/env python3
"""Lightkube resources for est.mitre.org."""

from typing import ClassVar

from lightkube.core.resource import (ApiInfo, NamespacedResourceG,
                                     NamespacedSubResource, ResourceDef)

import estissuer.models.est_mitre_org_v1alpha1 as est
from estissuer import GROUP


class EstIssuerStatus(NamespacedSubResource, est.EstIssuerStatus):
    """EstIssuer status subresource."""

    _api_info = ApiInfo(
        resource=ResourceDef(GROUP, est.VERSION, "EstIssuer"),
        plural="estissuers",
        verbs=["get", "patch", "put"],
        action="status",
    )


class EstIssuer(NamespacedResourceG, est.EstIssuer):
    """EstIssuer resource."""

    _api_info = ApiInfo(
        resource=ResourceDef(GROUP, est.VERSION, "EstIssuer"),
        plural="estissuers",
        verbs=[
            "delete",
            "deletecollection",
            "get",
            "list",
            "patch",
            "create",
            "update",
            "watch",
        ],
    )

    Status: ClassVar = EstIssuerStatus
