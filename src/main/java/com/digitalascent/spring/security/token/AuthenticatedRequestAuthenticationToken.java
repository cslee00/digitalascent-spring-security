package com.digitalascent.spring.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.annotation.Nullable;
import java.util.Collection;

import static com.google.common.base.Preconditions.checkNotNull;

public final class AuthenticatedRequestAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 123456L;

    private final Object principal;

    AuthenticatedRequestAuthenticationToken(Collection<? extends GrantedAuthority> authorities, Object principal, Object details) {
        super(authorities);
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
