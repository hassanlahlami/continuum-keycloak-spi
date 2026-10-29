package com.continuum.keycloak.auth;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

/** Minimal IPv4/IPv6 CIDR allowlist matcher. Anything unparsable never matches (fail-closed). */
final class CidrMatcher {

    private CidrMatcher() {
    }

    static List<String> split(String csv) {
        if (csv == null) {
            return List.of();
        }
        return Arrays.stream(csv.split("[,;\\s]+")).filter(s -> !s.isBlank()).toList();
    }

    static boolean matchesAny(String address, List<String> cidrs) {
        return cidrs.stream().anyMatch(c -> matches(address, c));
    }

    static boolean matches(String address, String cidr) {
        try {
            String[] parts = cidr.split("/", 2);
            byte[] net = literal(parts[0]);
            byte[] addr = literal(address);
            if (net.length != addr.length) {
                return false;
            }
            int bits = parts.length == 2 ? Integer.parseInt(parts[1]) : net.length * 8;
            if (bits < 0 || bits > net.length * 8) {
                return false;
            }
            for (int i = 0; i < bits; i += 8) {
                int mask = bits - i >= 8 ? 0xFF : (0xFF << (8 - (bits - i))) & 0xFF;
                if ((net[i / 8] & mask) != (addr[i / 8] & mask)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Literal IPs only: never triggers a DNS lookup. */
    private static byte[] literal(String ip) {
        if (ip == null || !ip.matches("[0-9a-fA-F:.]+")) {
            throw new IllegalArgumentException("not an IP literal");
        }
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
