#!/usr/bin/env python3
"""Suite-wide fixtures."""

from pathlib import Path

import pytest
from lightkube import codecs
from lightkube.config.kubeconfig import KubeConfig
from lightkube.core.client import Client
from lightkube.resources.apiextensions_v1 import CustomResourceDefinition

BASE = Path("manifests/crds")
APIS = [
    "estissuers.est.mitre.org", "estclusterissuers.est.mitre.org",
    "estorders.est.mitre.org"
]


@pytest.fixture(scope="session")
def client():
    return Client(config=KubeConfig.from_env())


@pytest.fixture(scope="session")
def resources(client):
    # install estissuer, estclusterissuer, estorder
    for crd in APIS:
        with open(BASE / f"{crd}.yaml") as f:
            for obj in codecs.load_all_yaml(f):
                client.create(obj)
    yield
    # delete estissuer, estclusterissuer, estorder
    for api in APIS:
        crd = client.get(CustomResourceDefinition, name=api)
        client.delete(CustomResourceDefinition, name=crd.metadata.name)
