#!/usr/bin/env python3
"""Kubernetes models."""
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional

from estissuer.models import DataClassJsonCamelMixIn

Time = datetime


@dataclass
class ManagedFieldsEntry(DataClassJsonCamelMixIn):
    """ManagedFieldsEntry model."""

    api_version: Optional[str]
    fields_type: Optional[str]
    fields_v1: Optional[Any]
    manager: Optional[str]
    operation: Optional[str]
    time: Optional[Time]


@dataclass
class OwnerReference(DataClassJsonCamelMixIn):
    """OwnerReference model."""

    api_version: Optional[str]
    block_owner_deletion: Optional[bool]
    controller: Optional[bool]
    kind: Optional[str]
    name: Optional[str]
    uid: Optional[str]


@dataclass
class ObjectMeta(DataClassJsonCamelMixIn):
    """Object metadata model."""

    annotations: Optional[dict]
    cluster_name: Optional[str]
    creation_time_stamp: Optional[Time]
    deletion_grace_period_seconds: Optional[int]
    deletion_time_stamp: Optional[Time]
    finalizers: Optional[List[str]]
    generate_name: Optional[str]
    generation: Optional[int]
    labels: Optional[dict]
    managed_fields: Optional[List[ManagedFieldsEntry]]
    name: str
    namespace: Optional[str]
    owner_References: Optional[List[OwnerReference]]
    resource_version: Optional[str]
    self_link: Optional[str]
    uid: Optional[str]
