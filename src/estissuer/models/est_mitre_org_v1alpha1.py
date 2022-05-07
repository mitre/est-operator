#!/usr/bin/env python3
"""Lightkube models for est.mitre.org CRDs."""

from dataclasses import dataclass
from typing import List, Optional

from lightkube.core.dataclasses_dict import DataclassDictMixIn
from lightkube.models.core_v1 import SecretReference
from lightkube.models.meta_v1 import ObjectMeta

GROUP = "est.mitre.org"
VERSION = "v1alpha1"


@dataclass
class EstCondition(DataclassDictMixIn):
    """EstCondition."""


@dataclass
class EstIssuerSpec(DataclassDictMixIn):
    """EstIssuerSpec model."""

    host: str
    cacert: str
    port: Optional[int] = 443
    label: Optional[str] = None
    secretRef: Optional[SecretReference] = None


@dataclass
class EstIssuerStatus(DataclassDictMixIn):
    """EstIssuerStatus."""

    conditions: Optional[List[EstCondition]] = None


@dataclass
class EstIssuer(DataclassDictMixIn):
    """EstIssuer model."""

    apiVesion: str = f"{GROUP}/{VERSION}"
    kind: str = "EstIssuer"
    metadata: Optional[ObjectMeta] = None
    spec: Optional[EstIssuerSpec] = None
    status: Optional[EstIssuerStatus] = None
