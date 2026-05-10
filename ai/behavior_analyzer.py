from ai.comment_engine import generate_comment

def analyze(open_ports):
    if 554 in open_ports or 1935 in open_ports:
        return generate_comment("streaming")
    if 27015 in open_ports or 3074 in open_ports:
        return generate_comment("gaming")
    if 21 in open_ports or 23 in open_ports or 445 in open_ports:
        return generate_comment("suspicious")
    if len(open_ports) > 20:
        return generate_comment("port_scan")
    return generate_comment("normal")
