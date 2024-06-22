#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Controller initialization methods."""

from importlib import resources

import kopf
from lightkube import codecs
from lightkube.config.kubeconfig import KubeConfig
from lightkube.core.client import Client


@kopf.on.startup()
def apply_crds(**_):
    """Apply controller CRDs on startup.

    NOTE: CRDs are NOT removed on shutdown.
    """
    crds = resources.files("estissuer.crds")
    client = Client(config=KubeConfig.from_env(), field_manager="est.mitre.org")
    for crd in crds.iterdir():
        with crd.open() as f:
            objs = codecs.load_all_yaml(f)
        for obj in objs:
            client.apply(obj)
