#!/usr/bin/env python

import base64
import tempfile
from datetime import datetime, timezone

import kopf
import kubernetes.client as k8s
import requests
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from dateutil.parser import parse

from estoperator.helpers import (GROUP, VERSION, WELLKNOWN, SSLContextAdapter,
                                 get_issuer_from_resource, get_owner_by_kind,
                                 get_secret_from_resource)


@kopf.on.create(
    GROUP,
    VERSION,
    "estorders",
    annotations={"estoperator-perm-fail": kopf.ABSENT},
)
def estorder_create(spec, patch, body, **_):
    """reconcile an EST request"""
    # gather resources
    issuer = get_issuer_from_resource(body)
    secret = get_secret_from_resource(issuer)
    if secret is None:
        raise kopf.TemporaryError(f"{spec['secretName']} not found")
    certreq = get_owner_by_kind(body, ["CertificateRequest"])
    # set parameters for enrollment
    cacert = base64.b64decode(issuer["spec"]["cacert"])
    request = base64.b64decode(spec["request"])
    baseUrl = f"https://{issuer['spec']['host']}:{issuer['spec'].get('port', 443)}"
    path = "/".join(i for i in [WELLKNOWN, issuer["spec"].get("label")] if i)
    kwargs = {}
    if spec["renewal"]:
        path = path + "/simplereenroll"
        certfile = tempfile.NamedTemporaryFile(suffix=".pem")
        tls_secret = get_secret_from_resource(
            get_owner_by_kind(certreq, ["Certificate"])
        )
        if tls_secret is None:
            raise kopf.TemporaryError("request is renewal but TLS secret missing")
        certfile.writelines(
            [
                base64.b64decode(tls_secret.data["tls.crt"]),
                b"\n",
                base64.b64decode(tls_secret.data["tls.key"]),
            ]
        )
        certfile.seek(0)
        kwargs["cert"] = certfile.name
    else:
        path = path + "/simpleenroll"
        kwargs["auth"] = (
            base64.b64decode(secret.data["username"]).decode(),
            base64.b64decode(secret.data["password"]).decode(),
        )
    # call portal API
    kopf.info(
        body,
        reason="Debugging",
        message=f"estorder_create: {certreq['metadata']['name']} at {baseUrl}{path}",
    )
    with tempfile.NamedTemporaryFile(suffix=".pem") as cafile:
        cafile.write(cacert)
        cafile.seek(0)
        session = requests.Session()
        session.mount(baseUrl, SSLContextAdapter())
        try:
            response = session.post(
                baseUrl + path,
                data=request,
                headers={
                    "Content-Type": "application/pkcs10",
                    "Content-Transfer-Encoding": "base64",
                },
                verify=cafile.name,
                **kwargs,
            )
        except (requests.exceptions.SSLError, requests.RequestException) as err:
            raise kopf.TemporaryError(err)
    # handle response
    kopf.info(
        body,
        reason="Debugging",
        message=f"estorder_create: {response.status_code} {response.reason}",
    )
    if spec["renewal"]:
        certfile.close()
    if 400 <= response.status_code < 500:
        kopf.exception(
            body,
            reason="RequestProblem",
            message=f"{response.reason}: {response.content}",
        )
        raise kopf.TemporaryError(
            f"{response.status_code}: {response.reason}", delay=600
        )
    if 500 <= response.status_code < 600:
        kopf.info(body, reason="ServerProblem", message=response.reason)
        raise kopf.TemporaryError(
            f"Server error: {response.status_code} {response.reason}", delay=600
        )
    if response.status_code not in [200, 202]:
        kopf.TemporaryError(
            f"Unexpected: {response.status_code} {response.reason} {response.content}"
        )
    if response.status_code == 202:
        kopf.info(body, reason="RequestPending", message=response.reason)
        after = response.headers["Retry-After"]
        if isinstance(after, str):
            if after.isnumeric():
                after = int(after)
            else:
                after = parse(after)
                after = after - datetime.now(timezone.utc)
                after = after.seconds
        raise kopf.TemporaryError("Reqest accepted pending issuance", delay=after)
    if response.status_code == 200:
        certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(response.content))
        cert = certs[0].public_bytes(Encoding.PEM)
        certreq["status"]["certificate"] = base64.b64encode(cert).decode()
        certreq["status"]["ca"] = issuer["spec"]["cacert"]
        certreq["status"]["conditions"] = [
            dict(
                lastTransitionTime=f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
                type="Ready",
                status="True",
                reason="Issued",
                message="certificate issued",
            )
        ]
        try:
            group, version = certreq["apiVersion"].split("/")
            api = k8s.CustomObjectsApi()
            _ = api.patch_namespaced_custom_object_status(
                group,
                version,
                certreq["metadata"]["namespace"],
                certreq["kind"].lower() + "s",
                certreq["metadata"]["name"],
                certreq,
            )
        except k8s.exceptions.OpenApiException as err:
            raise kopf.TemporaryError(eval(err.body)["message"])

    return {
        "certificate": base64.b64encode(cert).decode(),
    }
