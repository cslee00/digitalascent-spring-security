package com.digitalascent.spring.security.token;

import com.digitalascent.spring.security.AuthenticationDetails;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;

import java.util.function.Function;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public final class RequestTokenAuthenticationProvider implements AuthenticationProvider {

    private final Function<RequestAuthenticationToken, TokenDetails> tokenDetailsFunction;

    public RequestTokenAuthenticationProvider(Function<RequestAuthenticationToken, TokenDetails> tokenDetailsFunction) {
        this.tokenDetailsFunction = checkNotNull(tokenDetailsFunction, "tokenDetailsFunction is required");
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        checkNotNull(authentication, "authentication is required");
        checkArgument(supports(authentication.getClass()), "supports(authentication.getClass()) : %s", authentication);

        if( !supports( authentication.getClass())) {
            throw new AssertionError("Unexpected authentication token class: " + authentication );
        }

        TokenDetails tokenDetails = tokenDetailsFunction.apply((RequestAuthenticationToken) authentication);
        if( tokenDetails == null ) {
            throw new BadCredentialsException("Unable to locate credentials for " + authentication );
        }

        validateTokenDetails(tokenDetails);

        return new AuthenticatedRequestAuthenticationToken(tokenDetails, (AuthenticationDetails) authentication.getDetails());
    }

    private static void validateTokenDetails(TokenDetails tokenDetails) {
        if (!tokenDetails.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("Credentials expired");
        }

        if (!tokenDetails.isEnabled()) {
            throw new DisabledException("Token disabled");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
