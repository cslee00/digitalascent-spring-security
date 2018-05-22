package com.digitalascent.spring.security;

import com.google.common.base.MoreObjects;

import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticationDetails {
    private final String networkIpAddress;

    public AuthenticationDetails(String networkIpAddress) {
        this.networkIpAddress = checkNotNull(networkIpAddress, "networkIpAddress is required");
    }

    public String getNetworkIpAddress() {
        return networkIpAddress;
    }


    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("networkIpAddress", networkIpAddress)
                .toString();
    }
}
