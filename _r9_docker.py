import io

p = r"C:\Users\joxor\threatlens\backend\Dockerfile"
raw = io.open(p, "rb").read().decode("utf-8")

old = "EXPOSE 8000"
new = """# API keys for enrichment services (free tier — move to secrets manager in prod)
ENV ABUSEIPDB_KEY=fbd92005b94e67fbcfcddd15f59ec436316cf2a5ed423c52accc746d3d63ebf6ac042e1f2d8642fc
ENV VIRUSTOTAL_KEY=d274784ace04cb21702026e552dcda0cb136b8ce9373f4fcbf8b2b8de540659e
ENV SHODAN_KEY=8TT1YWLyzQ1sjyYWFHz5RJoOo0d4nADf
ENV GREYNOISE_KEY=hpGGwb4xsZeN0nLudRhCkbpfzo6jyqeLpd2JuJE4uVFDRAWV4Ul85oCdYtmnc2WV
ENV OTX_API_KEY=79de699754632127b4568c1912d21451e4e8cd2a947748335727fe5a7c04dd27
EXPOSE 8000"""
n = raw.count(old)
print("anchor:", n)
if n == 1:
    raw = raw.replace(old, new)
    io.open(p, "wb").write(raw.encode("utf-8"))
    print("OK  Dockerfile: API keys added as ENV")
