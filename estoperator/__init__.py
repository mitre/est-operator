#!/usr/bin/env python

#!/usr/bin/env python

import ctypes
import os
import ssl
from pathlib import Path

import lddwrap


def setup_fips(**kwargs):
    deps = lddwrap.list_dependencies(path=Path(ssl._ssl.__file__))
    libcrypto = [x.soname for x in deps if x.soname and "libcrypto" in x.soname]
    libcrypto = ctypes.CDLL(libcrypto[0])
    if not libcrypto.FIPS_mode_set(1):
        raise ssl.SSLError("FIPS mode failed to initialize")


if os.getenv("OPENSSL_FIPS") == "1":
    setup_fips()


from .certificaterequest import *
from .estissuer import *
from .estorder import *
from .helpers import *

if __name__ == "__main__":
    pass
