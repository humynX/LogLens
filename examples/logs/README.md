# Example Security Logs for LogLens Testing

This directory contains sample security logs for testing and demonstrating LogLens capabilities.

## Files

- `auth.log` - Linux authentication logs (syslog format)
- `windows_security.json` - Windows Security Event logs (JSON)
- `cloudtrail.json` - AWS CloudTrail logs
- `firewall.log` - Firewall logs (CEF format)
- `web_access.log` - Apache/Nginx access logs

## Usage

```bash
# Test with auth logs
loglens query "show failed logins" examples/logs/auth.log

# Test with Windows events
loglens hunt examples/logs/windows_security.json

# Interactive investigation
loglens investigate examples/logs/
```
