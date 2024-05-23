from panther_base_helpers import deep_get, pattern_match
import datetime

## Required

def rule(event):
    start_hour = 7
    end_hour = 20
    event_time = datetime.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    event_time_est = event_time - datetime.timedelta(hours=5)
    
    return 'Login failed' in event['message'] and not (start_hour <= event_time_est.hour < end_hour)

## Optional Functions

def title(event):
    return f"Failed login attempt by {event.get('identity')}"

def dedup(event):
    return event.get("identity")

def alert_context(event):
    return {
        "remote_ip": event.get("remote_ip"),
        "service": event.get("service"),
    }

def severity(event):
    return "HIGH"

def description(event):
    return f"Failed login attempt by {event.get('identity')} from IP {event.get('remote_ip')} outside permitted hours."

def reference(event):
    return f"https://docs.yourcompany.com/security/events#failed-login"

def runbook(event):
    return f"Investigate the failed login attempt by {event.get('identity')} from IP {event.get('remote_ip')}."
