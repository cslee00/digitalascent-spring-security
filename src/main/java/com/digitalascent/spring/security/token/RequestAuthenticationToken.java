package com.digitalascent.spring.security.token;

import com.digitalascent.spring.security.AuthenticationDetails;
import com.google.common.collect.ImmutableList;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

public final class RequestAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 123456L;

    private final String apiToken;

    public RequestAuthenticationToken(String apiToken, AuthenticationDetails details) {
        super(ImmutableList.of());
        this.apiToken = checkNotNull(apiToken, "apiToken is required");
        setDetails(checkNotNull(details, "details is required"));
    }

    @Override
    public Object getCredentials() {
        return apiToken;
    }

    @Override
    @Nullable
    public Object getPrincipal() {
        return null;
    }
}
