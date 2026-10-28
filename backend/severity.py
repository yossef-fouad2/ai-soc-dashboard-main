"""Investigation priority, not model confidence or a compromise assertion."""


def compute_severity(activity_type, methods):
    priorities = {
        "suspicious_login": ("Critical", "An accepted authentication follows an observed failure burst for the same identity/host; review promptly, without assuming compromise."),
        "brute_force": ("High", "Repeated explicit failed authentications meet the configured burst rule; investigate suspected brute force."),
        "port_scan": ("High", "Distinct destination ports meet the event-time scan rule; verify whether the probing is authorized."),
        "network_anomaly": ("Medium", "A calibrated network anomaly warrants review; the model does not identify an attack name or probability."),
    }
    level, reason = priorities.get(activity_type, ("Low", "Review the retained source evidence."))
    return level, {"reason": reason, "methods": list(methods), "meaning": "investigation priority, not detection confidence"}
