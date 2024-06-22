#!/usr/bin/env python3
"""Kubernetes models."""
from dataclasses import dataclass
from typing import Optional

from estissuer.models import DataClassJsonCamelMixIn

from estissuer.models.kubernetes_meta_v1 import ObjectMeta


@dataclass
class SecretReference(DataClassJsonCamelMixIn):
    """Secret reference."""

    name: Optional[str]
    namespace: Optional[str]


@dataclass
class Secret(DataClassJsonCamelMixIn):
    """Secret resource."""

    metadata: Optional[ObjectMeta]
    type: Optional[str]
    data: Optional[dict]
    string_data: Optional[dict]
    api_versions: str = "v1/Secret"
    kind: str = "Secret"
