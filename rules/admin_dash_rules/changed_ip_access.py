from panther_base_helpers import deep_get, pattern_match

# Track the last source IP for each identity
LAST_remote_ip = {}

def rule(event):
    identity = event.get("identity")
    remote_ip = event.get("remote_ip")

    if identity in LAST_remote_ip:
        if LAST_remote_ip[identity] != remote_ip:
            # Update the last source IP for the identity
            LAST_remote_ip[identity] = remote_ip
            return True
    else:
        # Initialize the last source IP for the identity
        LAST_remote_ip[identity] = remote_ip

    return False

def title(event):
    return f"identity {event.get('identity')} logged in from a different IP address"

def dedup(event):
    return event.get("identity")

def alert_context(event):
    return {
        "remote_ip": event.get("remote_ip"),
        "previous_ip": LAST_remote_ip[event.get("identity")],
        "service": event.get("service"),
    }

def severity(event):
    return "MEDIUM"

def description(event):
    return f"identity {event.get('identity')} logged in from IP {event.get('remote_ip')}, different from previous IP."

def reference(event):
    return "https://docs.yourcompany.com/security/events#login-from-different-ip"

def runbook(event):
    return f"Verify if the login attempt by {event.get('identity')} from a new IP address {event.get('remote_ip')} is legitimate."

