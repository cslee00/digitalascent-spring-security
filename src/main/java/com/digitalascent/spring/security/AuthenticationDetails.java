package com.digitalascent.spring.security;

import com.google.common.base.MoreObjects;

import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticationDetails {
    private final String networkIpAddress;
    private final String clientIpAddress;

    public AuthenticationDetails(String networkIpAddress, String clientIpAddress) {
        this.networkIpAddress = networkIpAddress;
        this.clientIpAddress = checkNotNull(clientIpAddress, "clientIpAddress is required");
    }

    public String getNetworkIpAddress() {
        return networkIpAddress;
    }

    public String getClientIpAddress() {
        return clientIpAddress;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("networkIpAddress", networkIpAddress)
                .add("clientIpAddress", clientIpAddress)
                .toString();
    }
}
