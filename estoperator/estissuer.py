#!/usr/bin/env python

import base64
import tempfile

import kopf
import pem
import requests
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from OpenSSL.crypto import (FILETYPE_PEM, X509Store, X509StoreContext,
                            X509StoreContextError, load_certificate)

from estoperator.helpers import (GROUP, VERSION, WELLKNOWN, SSLContextAdapter,
                                 get_secret_from_resource)


@kopf.on.create(
    GROUP,
    VERSION,
    "estissuers",
    annotations={"estoperator-perm-fail": kopf.ABSENT},
)
@kopf.on.create(
    GROUP,
    VERSION,
    "estclusterissuers",
    annotations={"estoperator-perm-fail": kopf.ABSENT},
)
def estissuer_create(spec, patch, body, **_):
    """validate and mark issuers as ready"""
    # Secret must exist and be the correct type
    secret = get_secret_from_resource(body)
    if secret is None:
        raise kopf.TemporaryError(f"{spec['secretName']} not found")
    baseUrl = f"https://{spec['host']}:{spec.get('port', 443)}"
    path = "/".join(i for i in [WELLKNOWN, spec.get("label"), "cacerts"])
    # fetch /cacerts using explicit TA
    cacert = base64.b64decode(spec["cacert"])
    with tempfile.NamedTemporaryFile(suffix=".pem") as cafile:
        cafile.write(cacert)
        cafile.seek(0)
        session = requests.Session()
        session.mount(baseUrl, SSLContextAdapter())
        try:
            response = session.get(baseUrl + path, verify=cafile.name)
        except (
            requests.exceptions.SSLError,
            requests.exceptions.RequestException,
        ) as err:
            patch.metadata.annotations["estoperator-perm-fail"] = "yes"
            raise kopf.PermanentError(err)
    # 200 OK is good, anything else is an error
    if response.status_code != 200:
        raise kopf.TemporaryError(
            f"Unexpected response: {response.status}, {response.reason}",
        )
    # configured cacert must be in EST portal bundle
    explicit = pem.parse(cacert)
    store = X509Store()
    _ = [
        store.add_cert(load_certificate(FILETYPE_PEM, cert.as_text()))
        for cert in explicit
    ]
    # cacert = x509.load_pem_x509_certificate(cacert)
    try:
        for leaf in pkcs7.load_der_pkcs7_certificates(
            base64.b64decode(response.content)
        ):
            context = X509StoreContext(
                store,
                load_certificate(FILETYPE_PEM, leaf.public_bytes(Encoding.PEM)),
            )
            context.verify_certificate()
    except X509StoreContextError as err:
        kopf.PermanentError(f"Unable to verify /cacerts content: {err}")
    return {"Ready": "True"}
