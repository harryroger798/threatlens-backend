"""TAXII 2.1 client adapter (FR-04). Fetches STIX 2.1 indicator objects
from a TAXII 2.1 server collection and normalises them to the canonical schema.

Feed configuration:
  transport: taxii21
  url: https://server/apiroots/{api_root}/collections/{collection_id}/objects/
  secret_ref: bearer:{token} | basic:{user}:{pass}

The adapter filters for STIX `indicator` objects, parses the STIX pattern
to extract the IOC type and value, and yields records in the canonical
ingest format."""

import re
from datetime import datetime, timezone

import httpx

TIMEOUT = 30.0
UA = {"User-Agent": "ThreatLens/1.0 (CTI platform)", "Accept": "application/taxii+json;version=2.1"}

_PATTERN_RE = re.compile(
    r"\[([\w-]+)(?:[:\w.':-]+)?\s*=\s*'([^']+)'"
)

_TYPE_MAP = {
    'ipv4-addr': 'ip',
    'ipv6-addr': 'ip',
    'domain-name': 'domain',
    'url': 'url',
    'email-addr': 'email',
    'file': 'hash_sha256',
    'windows-registry-key': None,
    'directory': None,
    'network-traffic': None,
}


def _parse_stix_pattern(pattern: str):
    """Extract IOC type and value from a STIX 2.1 comparison pattern."""
    if not pattern:
        return None
    m = _PATTERN_RE.search(pattern)
    if not m:
        return None
    obj_type = m.group(1).strip().lower()
    value = m.group(2).strip()
    mapped = _TYPE_MAP.get(obj_type)
    if mapped is None:
        return None
    if obj_type == 'file':
        pl = pattern.lower()
        if 'sha-256' in pl or 'sha256' in pl:
            mapped = 'hash_sha256'
        elif 'sha-1' in pl or 'sha1' in pl:
            mapped = 'hash_sha1'
        elif 'md5' in pl:
            mapped = 'hash_md5'
        else:
            mapped = 'hash_sha256'
    return (mapped, value)


def _parse_taxii_date(raw):
    if not raw:
        return None
    s = str(raw).strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def fetch_taxii21(feed) -> tuple[list[dict], str | None]:
    """Fetch STIX 2.1 indicator objects from a TAXII 2.1 collection.

    Returns (records, error). Records are in the canonical ingest format.
    """
    url = (feed.url or '').strip()
    secret = (feed.secret_ref or '').strip()
    if not url:
        return [], 'TAXII URL not configured'

    headers = dict(UA)
    if secret.startswith('bearer:'):
        headers['Authorization'] = f'Bearer {secret[7:]}'
    elif secret.startswith('basic:'):
        import base64
        creds = secret[6:]
        headers['Authorization'] = f'Basic {base64.b64encode(creds.encode()).decode()}'

    try:
        resp = httpx.get(url, headers=headers, timeout=TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        ct = resp.headers.get('content-type', '')
        if 'taxii' not in ct and 'json' not in ct:
            return [], f'unexpected content-type: {ct}'
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return [], f'TAXII server returned {exc.response.status_code}'
    except Exception as exc:
        return [], f'TAXII fetch failed: {exc}'

    objects = payload.get('objects', [])
    if not isinstance(objects, list):
        return [], 'TAXII response missing objects array'

    out = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'indicator':
            continue
        pattern = obj.get('pattern', '')
        parsed = _parse_stix_pattern(pattern)
        if not parsed:
            continue
        ioc_type, value = parsed
        created = _parse_taxii_date(obj.get('created'))
        modified = _parse_taxii_date(obj.get('modified'))
        seen = modified or created
        confidence = min(100, int(obj.get('confidence', 50)))
        labels = obj.get('labels', [])
        desc = obj.get('description', '')[:200] or None
        stix_id = obj.get('id', '')

        revoked = obj.get('revoked', False)
        if revoked:
            continue

        out.append({
            'value': value,
            'type': ioc_type,
            'seen_at': seen,
            'confidence': confidence,
            'description': desc,
            'malware_family': None,
            'tags': ['taxii', 'stix'] + [l.lower() for l in labels[:3] if l],
            'reference': stix_id,
            'tlp': feed.default_tlp,
        })

    return out, None
