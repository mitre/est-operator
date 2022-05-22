#!/usr/bin/env python3
"""Suite-wide fixtures."""

import pytest
from lightkube.config.kubeconfig import KubeConfig
from lightkube.core.client import Client


@pytest.fixture
def client():
    return Client(config=KubeConfig.from_env())
