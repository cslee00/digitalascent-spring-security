package com.digitalascent.spring.security.token;

import com.digitalascent.spring.security.AuthenticationDetails;
import com.google.common.collect.ImmutableList;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

public final class AuthenticatedRequestAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 123456L;

    private final Object principal;

    AuthenticatedRequestAuthenticationToken(Object principal, AuthenticationDetails details) {
        super(ImmutableList.of());
        this.principal = checkNotNull(principal, "principal is required");
        setAuthenticated(true);
        setDetails(checkNotNull(details, "details is required"));
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
