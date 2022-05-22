#!/usr/bin/env python3
"""Test estissuer lightkube resources."""

import pytest
from lightkube.generic_resource import create_namespaced_resource

import estissuer.resources.est_mitre_org_v1alpha1 as estres
from estissuer.models.est_mitre_org_v1alpha1 import VERSION

ESTISSUER = dict(
    metadata=dict(name="test", ),
    spec=dict(
        host="testrfc7030.com",
        port=8443,
        cacert="",
        secretRef=dict(
            name="",
            namespace="",
        ),
    ),
)


@pytest.fixture(scope="module")
def genEstIssuer(client, resources):
    return create_namespaced_resource(estres.GROUP, VERSION, "EstIssuer",
                                      "estissuers")


@pytest.fixture(scope="module")
def gen_test_issuer(client, genEstIssuer):
    generic = genEstIssuer(**ESTISSUER)
    client.create(generic)
    yield
    client.delete(genEstIssuer, name="test", namespace="default")


def test_get_estissuer(client, genEstIssuer, gen_test_issuer):
    generic = client.get(genEstIssuer, name="test", namespace="default")
    generic = generic.to_dict()
    # generic contains apiVersion and kind, which models hide from you
    del generic["apiVersion"]
    del generic["kind"]
    # get as estissuer
    custom = client.get(estres.EstIssuer, name="test", namespace="default")
    # assert same
    assert generic == custom.to_dict()
