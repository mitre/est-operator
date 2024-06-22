#!/usr/bin/env python3
"""Lightkube models for est.mitre.org CRDs."""

from dataclasses import dataclass
from typing import List, Optional
from estissuer.models import DataClassJsonCamelMixIn
from estissuer.models.kubernetes_meta_v1 import ObjectMeta
from estissuer.models.kubernetes_core_v1 import SecretReference

from estissuer import GROUP

VERSION = "v1alpha1"


@dataclass
class EstCondition(DataClassJsonCamelMixIn):
    """EstCondition."""


@dataclass
class EstIssuerSpec(DataClassJsonCamelMixIn):
    """EstIssuerSpec model."""

    host: str
    cacert: str
    port: Optional[int]
    label: Optional[str]
    secret_ref: Optional[SecretReference]


@dataclass
class EstIssuerStatus(DataClassJsonCamelMixIn):
    """EstIssuerStatus."""

    conditions: Optional[List[EstCondition]]


@dataclass
class EstIssuer(DataClassJsonCamelMixIn):
    """EstIssuer model."""

    metadata: Optional[ObjectMeta]
    spec: Optional[EstIssuerSpec]
    status: Optional[EstIssuerStatus]
    api_version: str = f"{GROUP}/{VERSION}"
    kind: str = "EstIssuer"


@dataclass
class EstClusterIssuer(DataClassJsonCamelMixIn):
    """EstClusterIssuer model."""

    metadata: Optional[ObjectMeta]
    spec: Optional[EstIssuerSpec]
    status: Optional[EstIssuerStatus]
    api_version: str = f"{GROUP}/{VERSION}"
    kind: str = "EstClusterIssuer"


# @dataclass
# @dataclass_json
# class EstOrderSpec:
#     """EstOrderSpec model."""


# @dataclass
# @dataclass_json
# class EstOrderStatus:
#     """EstOrderStatus model."""


# @dataclass
# @dataclass_json
# class EstOrder:
#     """EstOrder model."""

#     apiVersion: str = f"{GROUP}/{VERSION}"
#     kind: str = "EstOrder"
#     metadata: Optional[ObjectMeta] = None
#     spec: Optional[EstOrderSpec] = None
#     status: Optional[EstOrderStatus] = None
