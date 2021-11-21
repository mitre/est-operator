#!/usr/bin/env python3
"""pytest rigging."""

# import subprocess

# import kopf.testing
import pytest

# from kubernetes import client, config


# @pytest.fixture(scope="session")
# def with_infra():
#     """Provide CRDs and roles and rolebinding."""
#     subprocess.run(
#         "kubectl apply -k manifests/",
#         shell=True,
#         check=True,
#         timeout=10,
#         capture_output=True,
#     )
#     yield
#     subprocess.run(
#         "kubectl delete -k manifests/",
#         shell=True,
#         check=True,
#         timeout=10,
#         capture_output=True,
#     )


# @pytest.fixture(scope="session")
# def with_api():
#     """Provide CustomObjectApi."""
#     config.load_kube_config()
#     custom = client.CustomObjectsApi()
#     yield custom


# @pytest.fixture(scope="session")
# def with_runner(with_crd):
#     """Provide the controller."""
#     runner = kopf.testing.KopfRunner(["run", "-A", "--verbose", "-m", "estoperator"])
#     # This seems hacky but it effectively backgrounds the KOPF test runner.
#     # Without this indirection the finalizer gets called immeidately, and the
#     # controller doesn't act on any case.
#     with runner as dummy_runner:
#         yield runner
#     _ = dummy_runner  # Shuts up the linter


# @pytest.fixture(scope="session")
# def with_cases(with_crd):
#     """Provide Certificate test cases."""
#     subprocess.run(
#         "kubectl apply -k tests/manifests",
#         shell=True,
#         check=True,
#         timeout=10,
#         capture_output=True,
#     )
#     yield
#     subprocess.run(
#         "kubectl delete -k tests/manifests",
#         shell=True,
#         check=True,
#         timeout=10,
#         capture_output=True,
#     )
