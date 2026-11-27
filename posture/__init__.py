"""Security posture: an active TLS test of a virtual server and a security review
of the applications behind a load balancer.

The package is split so that other vendors can be added later:

    tls_scan.py   vendor-neutral: speaks TLS to an address and grades what it finds
    model.py      vendor-neutral: an application (a virtual server) and a finding
    rules.py      vendor-neutral: the review's rules, run over applications
    netscaler.py  NetScaler only: reads NITRO into applications, and the CLI that fixes a finding

An F5 BIG-IP or Avi adapter only has to produce the same applications (and its
own fix commands); the scanner, the rules, the scoring and the report stay as they are.
"""
