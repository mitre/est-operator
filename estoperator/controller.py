#!/usr/bin/env python3
"""Controller methods."""

import kopf


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Configure controller at startup."""
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="mimesis.mitre.org"
    )
