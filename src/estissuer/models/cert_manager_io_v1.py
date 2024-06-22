#!/usr/bin/env python3
"""Data models for cert-manager objects."""
from dataclasses import dataclass
from typing import List, Optional

from estissuer.models import DataClassJsonCamelMixIn
from estissuer.models.kubernetes_meta_v1 import ObjectMeta, Time

VERSION = "v1"
GROUP = "cert-manager.io"


@dataclass
class ObjectReference(DataClassJsonCamelMixIn):
    """ObjectReference model (from cert-manager.io API)."""

    name: str
    group: Optional[str]
    kind: Optional[str]


@dataclass
class CertificateRequestSpec(DataClassJsonCamelMixIn):
    """CertificateRequestSpec."""

    duration: Optional[int]
    issuer_ref: Optional[ObjectReference]
    request: Optional[str]
    is_ca: Optional[bool]
    usages: Optional[List[str]]
    username: Optional[str]
    uid: Optional[str]
    groups: Optional[List[str]]
    extra: Optional[dict]


@dataclass
class CertificateRequestCondition(DataClassJsonCamelMixIn):
    """CertificateRequestCondition."""

    type: Optional[str]
    status: Optional[str]
    last_transition_time: Optional[Time]
    reason: Optional[str]
    message: Optional[str]


@dataclass
class CertificateRequestStatus(DataClassJsonCamelMixIn):
    """CertificateRequestStatus."""

    conditions: List[CertificateRequestCondition]
    certificate: Optional[str]
    ca: Optional[str]
    failure_time: Optional[Time]


@dataclass
class CertificateRequest(DataClassJsonCamelMixIn):
    """CertificateRequest model."""

    metatdata: Optional[ObjectMeta]
    spec: Optional[CertificateRequestSpec]
    status: Optional[CertificateRequestStatus]
    api_version: str = f"{GROUP}/{VERSION}"
    kind: str = "CertificateRequest"
