# LogLens Example Logs

This directory contains sample logs for testing and demonstration.

## Files

- `auth_sample.log` - Linux authentication logs with attack simulation
- `windows_events.json` - Windows security events in JSON format
- `cloudtrail_sample.json` - AWS CloudTrail events
- `web_access.log` - Apache/Nginx style access logs

## Usage

```bash
# Analyze sample auth logs
loglens analyze examples/auth_sample.log

# Query for threats
loglens query "show me failed logins" examples/auth_sample.log

# Interactive investigation
loglens investigate examples/
```
