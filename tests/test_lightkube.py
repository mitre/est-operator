#!/usr/bin/env python3
"""Test estissuer lightkube resources."""

import estissuer.resources.est_mitre_org_v1alpha1 as estres
import pytest
from lightkube.generic_resource import create_namespaced_resource

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


@pytest.fixture
def estissuer_class(client):
    return create_namespaced_resource(estres.GROUP, estres.VERSION,
                                      "EstIssuer", "estissuers")


@pytest.fixture
def estissuer(client, estissuer_class):
    return estissuer_class(ESTISSUER)


def test_get_estissuer():
    # create via generic
    # get generic
    # get as estissuer
    # assert same
    pass
