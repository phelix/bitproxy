function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.bit")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.bit-tor")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.bit_tor")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.bit-i2p")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.bit_i2p")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }

    return "DIRECT";
    //return "PROXY 127.0.0.1:8084";
}
