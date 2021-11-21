#!/usr/bin/env python3

import pytest

from estoperator import request_ready, cert_ready, update_conditions

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


@pytest.fixture
def with_requests(with_api, with_controller, with_cases):
    """Provide CertificateRequests."""
    result = with_api.list_namespaced_custom_object(
        "cert-manager.io", "v1", "default", "certificaterequests"
    )
    return result["items"]


@pytest.fixture
def with_orders(with_api, with_controller, with_cases):
    """Provide EstOrders."""
    result = with_api.list_namespaced_custom_object(
        "est.mitre.org", "v1alpha1", "default", "estorders"
    )
    return result["items"]


@pytest.mark.parametrize("index", [0, 1])
def test_ca(index, with_requests):
    """Test that status.ca gets set."""
    assert with_requests[index].get("status", {}).get("ca")


def test_order_creation(with_orders):
    """EstOrders are created."""
    assert len(with_orders) == 2


@pytest.mark.parametrize("index", [0, 1])
def test_cr_order_status(index, with_requests, with_orders, with_controller):
    """CertificateRequest status.conditions updated with Pending when order is created."""
    conditions = with_requests[index]["status"].get("conditions")
    print(conditions)
    pending = [item["reason"] for item in conditions if item["type"] == "Ready"]
    assert len(pending) == 1
    assert "Pending" in pending


class TestUpdateConditions:
    """Tests for update_conditions()."""

    @pytest.fixture(scope="class")
    def with_conditions(self):
        """Provide conditions list."""
        return [
            {
                "type": "Ready",
                "status": "Unknown",
                "reason": "",
                "lastTransitionTime": "dummy",
            }
        ]

    @pytest.fixture(scope="class")
    def new_cond(self):
        """Provide new condition."""
        return {
            "type": "Approved",
            "status": "False",
            "reason": "",
            "lastTransitionTime": "flag",
        }

    @pytest.fixture(
        scope="class",
        params=[
            ({"status": "True"}, True),
            ({"reason": "Pending"}, True),
            ({"lastTransitionTime": "flag"}, False),
        ],
    )
    def replace_cond(self, request):
        """Provide replacement condition."""
        base = {
            "type": "Ready",
            "status": "Unknown",
            "reason": "",
            "lastTransitionTime": "dummy",
        }
        return {**base, **request.param[0]}, request.param[1]

    def test_update_conditions_new(self, with_conditions, new_cond):
        """Add new condition."""
        result = update_conditions(with_conditions, new_cond)
        assert len(result) == 2
        assert new_cond in result

    def test_update_conditions(self, with_conditions, replace_cond):
        """Replace condition."""
        cond, expected = replace_cond
        result = update_conditions(with_conditions, cond)
        assert len(result) == 1
        assert (cond in result) == expected
