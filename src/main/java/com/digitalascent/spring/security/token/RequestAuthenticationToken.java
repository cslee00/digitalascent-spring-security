package com.digitalascent.spring.security.token;

import com.digitalascent.common.base.SecureValues;
import com.digitalascent.spring.security.AuthenticationDetails;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

public final class RequestAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 123456L;

    private final String token;

    public RequestAuthenticationToken(String token, AuthenticationDetails details) {
        super(ImmutableList.of());
        this.token = checkNotNull(token, "token is required");
        setDetails(checkNotNull(details, "details is required"));
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    @Nullable
    public Object getPrincipal() {
        return null;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("token", SecureValues.maskTrailing(token,5))
                .toString();
    }
}
