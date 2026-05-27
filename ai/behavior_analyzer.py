from ai.comment_engine import generate_comment

def analyze(open_ports, services=None):
    services = services or {}
    port_set = set(open_ports)

    if 4444 in port_set or 6667 in port_set:
        return generate_comment("malware")
    if 2375 in port_set:
        return generate_comment("docker_exposed")
    if 6379 in port_set or 9200 in port_set or 11211 in port_set:
        return generate_comment("database_exposed")
    if 27017 in port_set or (445 in port_set and 3389 in port_set):
        return generate_comment("critical_target")
    if 21 in port_set or 23 in port_set or 445 in port_set:
        return generate_comment("suspicious")
    if 3389 in port_set or 5900 in port_set:
        return generate_comment("remote_access")
    if 3306 in port_set or 5432 in port_set or 1433 in port_set or 1521 in port_set:
        return generate_comment("database_exposed")
    if 554 in port_set or 8000 in port_set or 9010 in port_set:
        return generate_comment("streaming")
    if 80 in port_set or 443 in port_set or 8080 in port_set:
        return generate_comment("web_server")
    if 1935 in port_set:
        return generate_comment("streaming")
    if 27015 in port_set or 3074 in port_set:
        return generate_comment("gaming")
    if len(open_ports) > 20:
        return generate_comment("port_scan")
    if not open_ports:
        return generate_comment("stealth")
    return generate_comment("normal")
