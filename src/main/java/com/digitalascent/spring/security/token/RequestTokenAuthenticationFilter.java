package com.digitalascent.spring.security.token;

import com.digitalascent.logger.FluentLogger;
import com.google.common.base.Strings;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;

import static com.google.common.base.Preconditions.checkNotNull;

public final class RequestTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final FluentLogger logger = FluentLogger.forEnclosingClass();

    private final Function<HttpServletRequest, Optional<String>> tokenIdentifierFunction;
    private final AuthenticationManager authenticationManager;
    public RequestTokenAuthenticationFilter(Function<HttpServletRequest, Optional<String>> tokenIdentifierFunction,
                                            AuthenticationManager authenticationManager) {
        this.tokenIdentifierFunction = checkNotNull(tokenIdentifierFunction, "tokenIdentifierFunction is required");
        this.authenticationManager = checkNotNull(authenticationManager, "authenticationManager is required");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        WebAuthenticationDetails details = new WebAuthenticationDetails(request);
        Authentication suppliedAuthentication = null;
        try {
            Optional<String> optionalSuppliedToken = tokenIdentifierFunction.apply(request);
            if( !optionalSuppliedToken.isPresent() || Strings.isNullOrEmpty(optionalSuppliedToken.get())) {
                throw new BadCredentialsException("Missing authentication token");
            }

            suppliedAuthentication = new RequestAuthenticationToken(optionalSuppliedToken.get(), details);
            Authentication authResult = authenticationManager.authenticate(suppliedAuthentication);
            if (authResult == null) {
                throw new BadCredentialsException("Null value from authentication manager");
            }
            successfulAuthentication(request, response, authResult);

            filterChain.doFilter(request, response);
        } catch (AuthenticationException failed) {
            unsuccessfulAuthentication(request, response, failed, suppliedAuthentication == null ? new RequestAuthenticationToken("---missing token---", details) : suppliedAuthentication);
        }
    }

    private static void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
        SecurityContextHolder.getContext().setAuthentication(authResult);
    }

    private static void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed, Authentication authentication) {
        SecurityContextHolder.clearContext();
        if (failed instanceof InternalAuthenticationServiceException) {
            logger.atError().withCause(failed).log("An internal error occurred while trying to authenticate the request");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
