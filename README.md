## ReactGuard

React2Shell scanner powered by Xint.

ReactGuard provides framework- and vulnerability-detection tooling for CVE-2025-55182 (React2Shell) across frameworks that support React Server Components.
It also includes detectors for CVE-2025-55183, CVE-2025-55184, and CVE-2025-67779.

### Support status
- Next.js 14-16 and Waku 0.17-0.27: primary, validated coverage.
- Expo server actions, React Router server actions, and generic RSC: available but experimental.

### Install
```
pip install git+https://github.com/theori-io/reactguard.git
```

### CLI
```
reactguard http://host:port/              # Framework + vulnerability detection in one step

# Options
--json                    # emit machine-readable JSON
--ignore-ssl-errors       # skip TLS verification
```

### Python API
```python
from reactguard import ReactGuard

with ReactGuard() as rg:
    scan = rg.scan("https://xint.io/")
    print(scan)
```
