#!/usr/bin/env python3
"""EstOrder controller."""
import kopf

# EstOirder is created when a request is approved.
# - Fetch CA cert from issuer.
# - Fetch CSR from request.

@kopf.on.create("estorders")
def certificate
