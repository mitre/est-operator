#!/usr/bin/env python3
"""pytest rigging."""
import subprocess
import time

import kopf.testing
import pytest
from kubernetes import client, config


@pytest.fixture(scope="session")
def with_infra():
    """Provide CRDs and auto-approve rolebinding."""
    subprocess.run(
        "kubectl apply -k manifests/",
        shell=True,
        check=True,
        timeout=10,
        capture_output=True,
    )
    yield
    subprocess.run(
        "kubectl delete -k manifests/",
        shell=True,
        check=True,
        timeout=10,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def with_api():
    """Provide CustomObjectApi."""
    config.load_kube_config()
    custom = client.CustomObjectsApi()
    yield custom


@pytest.fixture(scope="session")
def with_controller(with_infra):
    """Provide the controller."""
    runner = kopf.testing.KopfRunner(["run", "-A", "--verbose", "-m", "estoperator"])
    # This seems hacky but it backgrounds the controller. Without this
    # indirection the pytest fixture finalizer gets called immediately, which
    # shuts down the controller.
    with runner as dummy_runner:
        yield runner
    _ = dummy_runner  # Shuts up the linter


@pytest.fixture(scope="session")
def with_cases(with_infra):
    """Provide Certificate test cases."""
    subprocess.run(
        "kubectl apply -k tests/manifests",
        shell=True,
        check=True,
        timeout=10,
        capture_output=True,
    )
    time.sleep(60)
    yield
    subprocess.run(
        "kubectl delete -k tests/manifests",
        shell=True,
        check=True,
        timeout=10,
        capture_output=True,
    )
