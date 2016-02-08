function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.bit")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    if (shExpMatch(host, "*.b")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }

    if (shExpMatch(host, "*._ipfs.bit")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.b-i")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.i")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }

    if (shExpMatch(host, "*._tor.bit")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.b-t")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.t")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }

    if (shExpMatch(host, "*._i2p.bit")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.b-2")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }
    if (shExpMatch(host, "*.2")) {
        return "PROXY 127.0.0.1:8084; DIRECT";
    }

    return "DIRECT";
    //return "PROXY 127.0.0.1:8084";
}
