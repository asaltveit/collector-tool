# collector-tool
It sends me an email containing all major Dependabot PRs, Dependabot alerts, and any non-major PRs that have been open for half an hour or more from a set of specified respositories.

Written in Python and YAML.

## Testing

Install test dependencies:
```bash
pip install -r requirements-dev.txt
```

Run all tests:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ -v --cov=scripts --cov-report=term-missing
```

Run specific test class (i.e. TestParseVersionChange):
```bash
pytest tests/test_check_dependabot_prs.py::TestParseVersionChange -v
```

