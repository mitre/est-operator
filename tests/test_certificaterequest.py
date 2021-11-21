#!/usr/bin/env python3

import pytest

from estoperator import request_ready, cert_ready

cases = [
    # approved & aligned ns
    ("request1", "default", "EstIssuer", "anchor1", True),
    # approved & misaligned ns
    ("request2", "other", "EstIssuer", "anchor1", False),
    # approved & cluster issuer
    ("request1", "default", "EstClusterIssuer", "anchor3", True),
    # not approved & aligned ns
    ("request3", "default", "EstIssuer", "anchor1", False),
    # not approved & cluster issuer
    ("request3", "other", "EstClusterIssuer", "anchor3", False),
    # approved & wrong issuer
    ("request1", "default", "Issuer", "anchor4", False),
]


@pytest.fixture
def with_approved_idx():
    """Provide approved_idx."""
    return {("default", "request1"): [True], ("other", "request2"): [True]}


@pytest.fixture
def with_anchor_idx():
    """Provide anchor_idx."""
    return {
        ("default", "anchor1"): [True],
        ("other", "anchor2"): [True],
        (None, "anchor3"): [True],
    }


@pytest.fixture
def with_orders_owner_idx():
    """Provide orders_owner_idx index."""
    return {
        ("default", "request"): [("default", "order")],
        ("other", "request2"): [("other", "order2")],
    }


@pytest.fixture
def with_orders_certs_idx():
    """Provide orders_certs_idx index."""
    return {("default", "order"): ["TESTVALUE"]}


@pytest.fixture(params=cases)
def with_cr(request):
    """CertificateRequest factory."""
    return {
        "metadata": {"name": request.param[0], "namespace": request.param[1]},
        "spec": {
            "issuerRef": {"kind": request.param[2], "name": request.param[3]},
        },
    }, request.param[4]


def test_request_ready(with_cr, with_anchor_idx, with_approved_idx):
    """Test request_ready method."""
    request, expected = with_cr
    namespace = request["metadata"]["namespace"]
    name = request["metadata"]["name"]
    spec = request["spec"]
    result = request_ready(namespace, name, spec, with_approved_idx, with_anchor_idx)
    assert bool(result) == expected


@pytest.mark.parametrize(
    "case, expected",
    [(("default", "request"), True), (("other", "request2"), False)],
)
def test_cert_ready(case, expected, with_orders_owner_idx, with_orders_certs_idx):
    """Test cert_ready method."""
    namespace, name = case
    result = cert_ready(namespace, name, with_orders_owner_idx, with_orders_certs_idx)
    assert result == expected
