"""Pytest configuration and shared fixtures."""
import pytest
from datetime import datetime, timezone


@pytest.fixture
def sample_pr_data():
    """Sample PR data for testing."""
    return {
        'title': 'Bump lodash from 4.17.20 to 4.17.21',
        'url': 'https://github.com/owner/repo/pull/123',
        'created_at': datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        'update_type': 'Patch',
        'number': 123
    }


@pytest.fixture
def sample_alert_data():
    """Sample alert data for testing."""
    return {
        'number': 1,
        'severity': 'high',
        'package': 'lodash',
        'summary': 'Prototype pollution in lodash',
        'url': 'https://github.com/owner/repo/security/dependabot/1',
        'cve_id': 'CVE-2021-23337'
    }