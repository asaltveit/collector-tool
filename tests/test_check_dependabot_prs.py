import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, patch, mock_open
import sys
import os

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts.check_dependabot_prs import (
    parse_version_change,
    load_repositories,
    get_dependabot_prs,
    get_dependabot_alerts,
    generate_email_body,
    send_email
)


class TestParseVersionChange:
    """Unit tests for version parsing logic."""
    
    def test_patch_update(self):
        title = "Bump lodash from 4.17.20 to 4.17.21"
        assert parse_version_change(title) == "Patch"
    
    def test_minor_update(self):
        title = "Bump react from 17.0.2 to 17.1.0"
        assert parse_version_change(title) == "Minor"
    
    def test_major_update(self):
        title = "Bump webpack from 4.46.0 to 5.0.0"
        assert parse_version_change(title) == "Major"
    
    def test_no_version_in_title(self):
        title = "Update dependencies"
        assert parse_version_change(title) == "Unknown"
    
    def test_keyword_detection(self):
        title = "major update to package"
        assert parse_version_change(title) == "Major"


class TestLoadRepositories:
    """Unit tests for repository loading."""
    
    def test_load_valid_config(self, tmp_path):
        # Create temporary config file
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "repositories.yml"
        config_file.write_text("""
        repositories:
        - owner/repo1
        - owner/repo2
        - owner/repo3
        """)
        
        with patch('builtins.open', mock_open(read_data=config_file.read_text())):
            repos = load_repositories()
            assert len(repos) == 3
            assert "owner/repo1" in repos
    
    def test_load_empty_config(self):
        with patch('builtins.open', mock_open(read_data="repositories: []")):
            repos = load_repositories()
            assert repos == []


class TestGetDependabotPRs:
    """Unit tests for fetching Dependabot PRs."""
    
    def test_filters_old_prs_or_major_updates(self):
        # Mock GitHub objects
        mock_github = Mock()
        mock_repo = Mock()
        mock_github.get_repo.return_value = mock_repo
        
        # Create mock PRs
        old_patch_pr = Mock()
        old_patch_pr.user.login = "dependabot[bot]"
        old_patch_pr.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        old_patch_pr.title = "Bump package from 1.0.0 to 1.0.1"
        old_patch_pr.html_url = "https://github.com/owner/repo/pull/1"
        old_patch_pr.number = 1
        
        recent_major_pr = Mock()
        recent_major_pr.user.login = "dependabot[bot]"
        recent_major_pr.created_at = datetime.now(timezone.utc) - timedelta(minutes=15)
        recent_major_pr.title = "Bump package from 1.0.0 to 2.0.0"
        recent_major_pr.html_url = "https://github.com/owner/repo/pull/2"
        recent_major_pr.number = 2
        
        recent_patch_pr = Mock()
        recent_patch_pr.user.login = "dependabot[bot]"
        recent_patch_pr.created_at = datetime.now(timezone.utc) - timedelta(minutes=15)
        recent_patch_pr.title = "Bump package from 1.0.0 to 1.0.1"
        recent_patch_pr.html_url = "https://github.com/owner/repo/pull/3"
        recent_patch_pr.number = 3
        
        mock_repo.get_pulls.return_value = [old_patch_pr, recent_major_pr, recent_patch_pr]
        
        prs = get_dependabot_prs("owner/repo", mock_github)
        
        # Should include: old patch PR (>1hr) and recent major PR
        # Should exclude: recent patch PR (<1hr and not major)
        assert len(prs) == 2
        pr_numbers = [pr['number'] for pr in prs]
        assert 1 in pr_numbers  # old patch
        assert 2 in pr_numbers  # recent major
        assert 3 not in pr_numbers  # recent patch (excluded)
    
    def test_filters_non_dependabot_prs(self):
        mock_github = Mock()
        mock_repo = Mock()
        mock_github.get_repo.return_value = mock_repo
        
        dependabot_pr = Mock()
        dependabot_pr.user.login = "dependabot[bot]"
        dependabot_pr.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        dependabot_pr.title = "Bump package from 1.0.0 to 1.0.1"
        dependabot_pr.html_url = "https://github.com/owner/repo/pull/1"
        dependabot_pr.number = 1
        
        human_pr = Mock()
        human_pr.user.login = "human-user"
        human_pr.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        
        mock_repo.get_pulls.return_value = [dependabot_pr, human_pr]
        
        prs = get_dependabot_prs("owner/repo", mock_github)
        
        assert len(prs) == 1
        assert prs[0]['title'] == "Bump package from 1.0.0 to 1.0.1"
    
    def test_handles_repo_access_error(self):
        mock_github = Mock()
        mock_github.get_repo.side_effect = Exception("Access denied")
        
        prs = get_dependabot_prs("owner/repo", mock_github)
        
        assert prs == []

# TODO: Is this testing correctly if I'm not receiving alerts?
class TestGetDependabotAlerts:
    """Unit tests for fetching Dependabot alerts."""
    
    def test_returns_open_alerts(self):
        mock_github = Mock()
        mock_repo = Mock()
        mock_github.get_repo.return_value = mock_repo
        
        # Mock alert
        mock_alert = Mock()
        mock_alert.number = 1
        mock_alert.security_advisory.severity = "high"
        mock_alert.security_vulnerability.package.name = "lodash"
        mock_alert.security_advisory.summary = "Prototype pollution"
        mock_alert.html_url = "https://github.com/owner/repo/security/dependabot/1"
        mock_alert.security_advisory.cve_id = "CVE-2021-23337"
        
        mock_repo.get_dependabot_alerts.return_value = [mock_alert]
        
        alerts = get_dependabot_alerts("owner/repo", mock_github)
        
        assert len(alerts) == 1
        assert alerts[0]['severity'] == "high"
        assert alerts[0]['package'] == "lodash"
        assert alerts[0]['cve_id'] == "CVE-2021-23337"
    
    def test_handles_alerts_access_error(self):
        mock_github = Mock()
        mock_github.get_repo.side_effect = Exception("Access denied")
        
        alerts = get_dependabot_alerts("owner/repo", mock_github)
        
        assert alerts == []


class TestGenerateEmailBody:
    """Unit tests for email generation."""
    
    def test_generates_empty_report(self):
        repo_data = {}
        html = generate_email_body(repo_data)
        
        assert "No Dependabot alerts or PRs" in html
        assert "<html>" in html
    
    def test_excludes_repos_without_data(self):
        repo_data = {
            "owner/repo1": {"alerts": [], "prs": []},
            "owner/repo2": {"alerts": [], "prs": []}
        }
        html = generate_email_body(repo_data)
        
        assert "owner/repo1" not in html
        assert "owner/repo2" not in html
    
    def test_includes_repos_with_alerts(self):
        repo_data = {
            "owner/repo1": {
                "alerts": [{
                    'number': 1,
                    'severity': 'high',
                    'package': 'lodash',
                    'summary': 'Test vulnerability',
                    'url': 'https://github.com/test',
                    'cve_id': 'CVE-2021-1234'
                }],
                "prs": []
            }
        }
        html = generate_email_body(repo_data)
        
        assert "owner/repo1" in html
        assert "lodash" in html
        assert "HIGH" in html
        assert "CVE-2021-1234" in html
    
    def test_includes_repos_with_prs(self):
        repo_data = {
            "owner/repo1": {
                "alerts": [],
                "prs": [{
                    'title': 'Bump lodash from 4.17.20 to 4.17.21',
                    'url': 'https://github.com/test/pull/1',
                    'created_at': datetime.now(timezone.utc) - timedelta(days=2),
                    'update_type': 'Patch',
                    'number': 1
                }]
            }
        }
        html = generate_email_body(repo_data)
        
        assert "owner/repo1" in html
        assert "Bump lodash" in html
        assert "Patch" in html
    
    def test_sorts_alerts_by_severity(self):
        repo_data = {
            "owner/repo1": {
                "alerts": [
                    {'number': 1, 'severity': 'low', 'package': 'pkg1', 'summary': 'Low', 'url': 'url1', 'cve_id': None},
                    {'number': 2, 'severity': 'critical', 'package': 'pkg2', 'summary': 'Critical', 'url': 'url2', 'cve_id': None},
                    {'number': 3, 'severity': 'high', 'package': 'pkg3', 'summary': 'High', 'url': 'url3', 'cve_id': None},
                ],
                "prs": []
            }
        }
        html = generate_email_body(repo_data)
        
        # Check that critical appears before high, and high before low
        critical_pos = html.find('CRITICAL')
        high_pos = html.find('HIGH')
        low_pos = html.find('LOW')
        
        assert critical_pos < high_pos < low_pos


class TestSendEmail:
    """Unit tests for email sending."""
    
    @patch('smtplib.SMTP_SSL')
    def test_sends_email_successfully(self, mock_smtp):
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        
        send_email(
            "Test Subject",
            "<html><body>Test</body></html>",
            "test@example.com",
            "password123"
        )
        
        mock_server.login.assert_called_once_with("test@example.com", "password123")
        mock_server.send_message.assert_called_once()
    
    @patch('smtplib.SMTP_SSL')
    def test_handles_email_send_failure(self, mock_smtp):
        mock_smtp.return_value.__enter__.side_effect = Exception("SMTP Error")
        
        with pytest.raises(SystemExit):
            send_email(
                "Test Subject",
                "<html><body>Test</body></html>",
                "test@example.com",
                "password123"
            )


class TestIntegration:
    """Integration tests for the full workflow."""
    
    @patch('scripts.check_dependabot_prs.Github')
    @patch('scripts.check_dependabot_prs.send_email')
    @patch('scripts.check_dependabot_prs.load_repositories')
    def test_full_workflow_with_data(self, mock_load_repos, mock_send_email, mock_github_class):
        # Setup
        mock_load_repos.return_value = ["owner/repo1"]
        
        mock_github = Mock()
        mock_github_class.return_value = mock_github
        
        mock_repo = Mock()
        mock_github.get_repo.return_value = mock_repo
        
        # Mock alert
        mock_alert = Mock()
        mock_alert.number = 1
        mock_alert.security_advisory.severity = "high"
        mock_alert.security_vulnerability.package.name = "test-package"
        mock_alert.security_advisory.summary = "Test vulnerability"
        mock_alert.html_url = "https://github.com/test"
        mock_alert.security_advisory.cve_id = "CVE-2021-1234"
        
        mock_repo.get_dependabot_alerts.return_value = [mock_alert]
        
        # Mock PR
        mock_pr = Mock()
        mock_pr.user.login = "dependabot[bot]"
        mock_pr.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
        mock_pr.title = "Bump package from 1.0.0 to 1.0.1"
        mock_pr.html_url = "https://github.com/test/pull/1"
        mock_pr.number = 1
        
        mock_repo.get_pulls.return_value = [mock_pr]
        
        # Set environment variables
        with patch.dict(os.environ, {
            'GITHUB_TOKEN': 'test_token',
            'GMAIL_ADDRESS': 'test@example.com',
            'GMAIL_APP_PASSWORD': 'test_password'
        }):
            # Import and run main (this would need to be refactored slightly)
            from scripts.check_dependabot_prs import main
            
            with patch('builtins.open', mock_open()):
                main()
        
        # Verify email was sent
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args
        
        assert "1 Alert" in call_args[0][0]  # subject
        assert "1 PR" in call_args[0][0]
        assert "test-package" in call_args[0][1]  # body
