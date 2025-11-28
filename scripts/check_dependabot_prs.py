#!/usr/bin/env python3
import os
import sys
import yaml
import smtplib
import re
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from github import Github
from typing import List, Dict, Any

def load_repositories() -> List[str]:
    """Load repository list from config file."""
    with open('config/repositories.yml', 'r') as f:
        config = yaml.safe_load(f)
    return config.get('repositories', [])

def parse_version_change(pr_title: str) -> str:
    """
    Determine if the update is patch, minor, or major.
    Looks for version patterns in PR title like: x.y.z to a.b.c
    """
    # Common Dependabot title patterns:
    # "Bump package from 1.2.3 to 1.2.4"
    # "Update package requirement from ~> 1.2 to ~> 2.0"
    
    version_pattern = r'(\d+)\.(\d+)\.(\d+)'
    versions = re.findall(version_pattern, pr_title)
    
    if len(versions) >= 2:
        old_ver = [int(x) for x in versions[0]]
        new_ver = [int(x) for x in versions[1]]
        
        if new_ver[0] > old_ver[0]:
            return "Major"
        elif new_ver[1] > old_ver[1]:
            return "Minor"
        elif new_ver[2] > old_ver[2]:
            return "Patch"
    
    # Fallback: check for keywords in title
    title_lower = pr_title.lower()
    if 'major' in title_lower:
        return "Major"
    elif 'minor' in title_lower:
        return "Minor"
    elif 'patch' in title_lower:
        return "Patch"
    
    return "Unknown"

# TODO: didn't receive the alert for map, just PR
def get_dependabot_alerts(repo_full_name: str, github_client: Github) -> List[Dict[str, Any]]:
    """Get all open Dependabot security alerts for a repository."""
    try:
        repo = github_client.get_repo(repo_full_name)
        
        # Use GitHub API to get Dependabot alerts
        alerts = repo.get_dependabot_alerts(state='open')
        
        alert_list = []
        for alert in alerts:
            alert_list.append({
                'number': alert.number,
                'severity': alert.security_advisory.severity,
                'package': alert.security_vulnerability.package.name,
                'summary': alert.security_advisory.summary,
                'url': alert.html_url,
                'cve_id': alert.security_advisory.cve_id
            })
        
        return alert_list
    
    except Exception as e:
        print(f"Error accessing Dependabot alerts for {repo_full_name}: {e}")
        return []

def get_dependabot_prs(repo_full_name: str, github_client: Github) -> List[Dict[str, Any]]:
    """Get all Dependabot PRs open for more than 1 hour for a repository."""
    try:
        repo = github_client.get_repo(repo_full_name)
        pulls = repo.get_pulls(state='open', sort='created', direction='desc')
        
        dependabot_prs = []
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        
        for pr in pulls:
            # Check if PR is from Dependabot
            if pr.user.login in ['dependabot[bot]', 'dependabot-preview[bot]']:
                # Check if PR is older than 1 hour
                if pr.created_at < one_hour_ago:
                    update_type = parse_version_change(pr.title)
                    dependabot_prs.append({
                        'title': pr.title,
                        'url': pr.html_url,
                        'created_at': pr.created_at,
                        'update_type': update_type,
                        'number': pr.number
                    })
        
        return dependabot_prs
    
    except Exception as e:
        print(f"Error accessing repository {repo_full_name}: {e}")
        return []

def generate_email_body(repo_data: Dict[str, Dict[str, Any]]) -> str:
    """Generate HTML email body with alerts and PR information."""
    
    # Check if there's any data to report
    has_data = any(data['alerts'] or data['prs'] for data in repo_data.values())
    
    if not has_data:
        return """
        <html>
        <body>
            <h2>Dependabot Weekly Report</h2>
            <p>No Dependabot alerts or PRs (open for more than 1 hour) across monitored repositories.</p>
            <p><em>Report generated on {}</em></p>
        </body>
        </html>
        """.format(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    
    html = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h2 { color: #24292e; }
            h3 { color: #24292e; margin-top: 25px; }
            h4 { color: #586069; margin-top: 15px; margin-bottom: 10px; }
            .repo-section { margin-bottom: 30px; border: 1px solid #e1e4e8; padding: 15px; border-radius: 6px; }
            .alert-item { 
                margin: 10px 0; 
                padding: 12px; 
                border-left: 4px solid #d73a49; 
                background-color: #fff5f5;
            }
            .pr-item { 
                margin: 15px 0; 
                padding: 10px; 
                border-left: 3px solid #0366d6; 
                background-color: #f6f8fa;
            }
            .alert-title { font-weight: bold; margin-bottom: 5px; }
            .pr-title { font-weight: bold; margin-bottom: 5px; }
            .alert-meta, .pr-meta { font-size: 0.9em; color: #586069; }
            .severity-badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.85em;
                font-weight: bold;
                margin-right: 8px;
            }
            .critical { background-color: #8b0000; color: white; }
            .high { background-color: #d73a49; color: white; }
            .medium { background-color: #fb8532; color: white; }
            .low { background-color: #ffd33d; color: #24292e; }
            .update-badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.85em;
                font-weight: bold;
                margin-left: 10px;
            }
            .major { background-color: #d73a49; color: white; }
            .minor { background-color: #fb8532; color: white; }
            .patch { background-color: #28a745; color: white; }
            .unknown { background-color: #6a737d; color: white; }
            a { color: #0366d6; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .section-divider { border-top: 1px solid #e1e4e8; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h2>Dependabot Weekly Report</h2>
    """
    
    total_alerts = 0
    total_prs = 0
    
    for repo_name, data in sorted(repo_data.items()):
        alerts = data['alerts']
        prs = data['prs']
        
        # Skip repositories with no alerts and no PRs
        if not alerts and not prs:
            continue
            
        total_alerts += len(alerts)
        total_prs += len(prs)
        
        html += f"""
        <div class="repo-section">
            <h3>📦 {repo_name}</h3>
        """
        
        # Add security alerts section
        if alerts:
            # Sort alerts by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_alerts = sorted(alerts, key=lambda x: severity_order.get(x['severity'], 999))
            
            html += f"""
            <h4>🚨 Security Alerts ({len(alerts)})</h4>
            """
            
            for alert in sorted_alerts:
                cve_display = f" ({alert['cve_id']})" if alert['cve_id'] else ""
                html += f"""
            <div class="alert-item">
                <div class="alert-title">
                    <span class="severity-badge {alert['severity']}">{alert['severity'].upper()}</span>
                    <a href="{alert['url']}" target="_blank">{alert['package']}{cve_display}</a>
                </div>
                <div class="alert-meta">
                    {alert['summary']}
                </div>
            </div>
                """
        
        # Add PRs section
        if prs:
            html += f"""
            <h4>🔄 Open Pull Requests ({len(prs)})</h4>
            """
            
            for pr in prs:
                badge_class = pr['update_type'].lower()
                days_open = (datetime.now(timezone.utc) - pr['created_at']).days
                
                html += f"""
            <div class="pr-item">
                <div class="pr-title">
                    <a href="{pr['url']}" target="_blank">#{pr['number']}: {pr['title']}</a>
                    <span class="update-badge {badge_class}">{pr['update_type']}</span>
                </div>
                <div class="pr-meta">
                    Opened {days_open} day{'s' if days_open != 1 else ''} ago • 
                    {pr['created_at'].strftime('%Y-%m-%d %H:%M UTC')}
                </div>
            </div>
                """
        
        html += """
        </div>
        """
    
    html += f"""
        <hr>
        <p><strong>Summary:</strong></p>
        <ul>
            <li>{total_alerts} open security alert{'s' if total_alerts != 1 else ''}</li>
            <li>{total_prs} open Dependabot PR{'s' if total_prs != 1 else ''}</li>
        </ul>
        <p><em>Report generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</em></p>
    </body>
    </html>
    """
    
    return html

def send_email(subject: str, body: str, gmail_address: str, gmail_password: str):
    """Send email via Gmail SMTP."""
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = gmail_address
    msg['To'] = gmail_address
    
    html_part = MIMEText(body, 'html')
    msg.attach(html_part)
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(gmail_address, gmail_password)
            server.send_message(msg)
        print(f"✓ Email sent successfully to {gmail_address}")
    except Exception as e:
        print(f"✗ Failed to send email: {e}")
        sys.exit(1)

def main():
    # Load environment variables
    github_token = os.environ.get('GITHUB_TOKEN')
    gmail_address = os.environ.get('GMAIL_ADDRESS')
    gmail_password = os.environ.get('GMAIL_APP_PASSWORD')
    
    if not all([github_token, gmail_address, gmail_password]):
        print("Error: Missing required environment variables")
        sys.exit(1)
    
    # Initialize GitHub client
    g = Github(github_token)
    
    # Load repositories
    repositories = load_repositories()
    print(f"Checking {len(repositories)} repositories for Dependabot alerts and PRs...")
    
    # Collect alerts and PRs from all repositories
    repo_data = {}
    for repo_name in repositories:
        print(f"\nChecking {repo_name}...")
        
        # Get security alerts
        alerts = get_dependabot_alerts(repo_name, g)
        if alerts:
            print(f"  Found {len(alerts)} security alert(s)")
            for alert in alerts:
                print(f"    - {alert['severity'].upper()}: {alert['package']}")
        else:
            print(f"  No security alerts")
        
        # Get PRs
        prs = get_dependabot_prs(repo_name, g)
        if prs:
            print(f"  Found {len(prs)} Dependabot PR(s)")
        else:
            print(f"  No Dependabot PRs")
        
        # Store data only if there are alerts or PRs
        if alerts or prs:
            repo_data[repo_name] = {
                'alerts': alerts,
                'prs': prs
            }
    
    # Generate email
    email_body = generate_email_body(repo_data)
    
    # Save report locally (optional, for artifacts)
    with open('dependabot_report.html', 'w') as f:
        f.write(email_body)
    
    # Send email
    total_alerts = sum(len(data['alerts']) for data in repo_data.values())
    total_prs = sum(len(data['prs']) for data in repo_data.values())
    subject = f"Dependabot Report - {total_alerts} Alert{'s' if total_alerts != 1 else ''}, {total_prs} PR{'s' if total_prs != 1 else ''}"
    send_email(subject, email_body, gmail_address, gmail_password)
    
    print(f"\n✓ Report complete! Found {total_alerts} alert(s) and {total_prs} PR(s)")
    print(f"  Included {len(repo_data)} repositor{'ies' if len(repo_data) != 1 else 'y'} with activity")

if __name__ == '__main__':
    main()