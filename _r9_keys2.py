import io

p = r"C:\Users\joxor\threatlens\backend\app\services\enrichment.py"
raw = io.open(p, "rb").read().decode("utf-8")

# the _get_env_key function exists but has no _FREE_TIER_KEYS fallback dict
# replace it with one that checks env vars first, then free-tier defaults
old_fn = 'def _get_env_key(name: str) -> str:\n    return os.environ.get(name, "")'
new_fn = (
    '_FREE_TIER_KEYS = {\n'
    '    "ABUSEIPDB_KEY": "fbd92005b94e67fbcfcddd15f59ec436316cf2a5ed423c52accc746d3d63ebf6ac042e1f2d8642fc",\n'
    '    "VIRUSTOTAL_KEY": "d274784ace04cb21702026e552dcda0cb136b8ce9373f4fcbf8b2b8de540659e",\n'
    '    "SHODAN_KEY": "8TT1YWLyzQ1sjyYWFHz5RJoOo0d4nADf",\n'
    '    "GREYNOISE_KEY": "hpGGwb4xsZeN0nLudRhCkbpfzo6jyqeLpd2JuJE4uVFDRAWV4Ul85oCdYtmnc2WV",\n'
    '    "OTX_API_KEY": "79de699754632127b4568c1912d21451e4e8cd2a947748335727fe5a7c04dd27",\n'
    '}\n\n'
    'def _get_env_key(name: str) -> str:\n'
    '    return os.environ.get(name, "") or _FREE_TIER_KEYS.get(name, "")'
)
n = raw.count(old_fn)
print('anchor:', n)
if n == 1:
    raw = raw.replace(old_fn, new_fn)
    io.open(p, "wb").write(raw.encode("utf-8"))
    print("OK  enrichment.py: free-tier keys embedded as defaults")
