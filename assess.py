"""Small HTTP baseline assessment. Only literal loopback targets are accepted."""
import argparse
import ipaddress
import json
import urllib.request
from urllib.parse import urlsplit


def validate_target(url):
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.username or parts.password or parts.fragment:
        raise ValueError('Use an HTTP loopback URL without credentials or fragment')
    try:
        addr = ipaddress.ip_address(parts.hostname or '')
    except ValueError as exc:
        raise ValueError('Literal loopback IP required, such as 127.0.0.1') from exc
    if not addr.is_loopback:
        raise ValueError('Only loopback targets are permitted')
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirect refused: inspect the destination manually')


def review(headers):
    h = {k.lower(): v for k, v in headers.items()}
    findings = []
    for header, title in [('content-security-policy', 'Missing Content Security Policy'),
                          ('x-content-type-options', 'Missing MIME sniffing protection'),
                          ('referrer-policy', 'Missing referrer policy')]:
        if not h.get(header):
            findings.append(dict(id=header, severity='informational', title=title, evidence='Header absent'))
    if h.get('x-content-type-options') and h['x-content-type-options'].lower() != 'nosniff':
        findings.append(dict(id='invalid-nosniff', severity='low', title='Unexpected MIME protection value', evidence=h['x-content-type-options']))
    if 'unsafe-inline' in h.get('content-security-policy', ''):
        findings.append(dict(id='csp-review', severity='informational', title='Review inline script policy', evidence=h['content-security-policy']))
    return findings


def assess(url):
    validate_target(url)
    # No environment proxy; redirects refused to keep requests inside the lab.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(urllib.request.Request(url, headers={'User-Agent': 'LocalPortfolioLab/1.0'}), timeout=5) as response:
        return dict(target=url, status=response.status, findings=review(dict(response.headers)))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('url')
    print(json.dumps(assess(p.parse_args().url), indent=2))
