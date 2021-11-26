#!/usr/bin/env python3
"""pytest rigging."""
import subprocess
import time
from pathlib import Path

import kopf.testing
import pytest
from kubernetes import client, config
from yaml import safe_load, safe_load_all

config.load_kube_config()


def provision_ns_cr(manifest):
    """Provision namespaced custom resource."""
    api = client.CustomObjectsApi()
    group, version = manifest["apiVersion"].split("/")
    namespace = manifest["metadata"].get("namespace", "default")
    plural = manifest["kind"].lower() + "s"
    _ = api.create_namespaced_custom_object(group, version, namespace, plural, manifest)


def get_ns_cr(manifest):
    """Retrieve namespaced custom resource."""
    api = client.CustomObjectsApi()
    group, version = manifest["apiVersion"].split("/")
    namespace = manifest["metadata"].get("namespace", "default")
    plural = manifest["kind"].lower() + "s"
    name = manifest["metadata"]["name"]
    return api.get_namespaced_custom_object(group, version, namespace, plural, name)


def deprovision_ns_cr(manifest):
    """Delete namespaced custom resource."""
    api = client.CustomObjectsApi()
    group, version = manifest["apiVersion"].split("/")
    namespace = manifest["metadata"].get("namespace", "default")
    plural = manifest["kind"].lower() + "s"
    name = manifest["metadata"]["name"]
    _ = api.delete_namespaced_custom_object(group, version, namespace, plural, name)


def provision_secret(manifest):
    """Provision secret resource."""
    api = client.CoreV1Api()
    namespace = manifest["metadata"].get("namespace", "default")
    _ = api.create_namespaced_secret(namespace, manifest)


def deprovision_secret(manifest):
    """Delete secret resource."""
    api = client.CoreV1Api()
    namespace = manifest["metadata"].get("namespace", "default")
    name = manifest["metadata"]["name"]
    _ = api.delete_namespaced_secret(name, namespace)


@pytest.fixture(scope="session")
def cr_api():
    """Provide k8s CustomObjectApi."""
    return client.CustomObjectsApi()


@pytest.fixture(scope="session")
def core_api():
    """Provide k8s CoreV1Api."""
    return client.CoreV1Api()


@pytest.fixture(scope="session")
def apiext_api():
    """Provide k8s ApiExtensions."""
    return client.ApiextensionsV1Api()


@pytest.fixture(scope="session")
def with_crd(apiext_api):
    """Provision est.mitre.org CRDs."""
    issuers = safe_load(open(Path("manifests/crds/est.mitre.org_estissuers.yaml"), "r"))
    c_issuers = safe_load(
        open(Path("manifests/crds/est.mitre.org_estclusterissuers.yaml"), "r")
    )
    orders = safe_load(open(Path("manifests/crds/est.mitre.org_estorders.yaml"), "r"))
    for crd in [issuers, c_issuers, orders]:
        _ = apiext_api.create_custom_resource_definition(crd)
    yield
    for crd in [issuers, c_issuers, orders]:
        _ = apiext_api.delete_custom_resource_definition(crd["metadata"]["name"])


@pytest.fixture(scope="session")
def testrfc7030_ns(with_crd, core_api, cr_api):
    """Provision working EstIssuer."""
    issuer, secret = list(
        safe_load_all(open(Path("tests/manifests/estissuers/testrfc7030.yaml"), "r"))
    )
    _ = provision_secret(secret)
    _ = provision_ns_cr(issuer)
    yield
    _ = deprovision_ns_cr(issuer)
    _ = deprovision_secret(secret)


@pytest.fixture(scope="session")
def controller(with_crd):
    """Provide the controller."""
    controller = kopf.testing.KopfRunner(
        ["run", "-A", "--verbose", "-m", "estoperator"]
    )
    # This seems hacky but it seems to be the only way to background kopf.
    # Without this indirection pytest seems to finalize the context immediately,
    # which shuts down the controller.
    with controller as dummy:
        yield controller
    _ = dummy  # Shuts up the linter
