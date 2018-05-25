package com.digitalascent.spring.security.token;

import com.google.common.base.Strings;
import org.springframework.security.authentication.AuthenticationEventPublisher;
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

    private final Function<HttpServletRequest, Optional<String>> tokenIdentifierFunction;
    private final AuthenticationManager authenticationManager;
    private final AuthenticationEventPublisher authenticationEventPublisher;
    public RequestTokenAuthenticationFilter(Function<HttpServletRequest, Optional<String>> tokenIdentifierFunction,
                                            AuthenticationManager authenticationManager,
                                            AuthenticationEventPublisher authenticationEventPublisher) {
        this.tokenIdentifierFunction = checkNotNull(tokenIdentifierFunction, "tokenIdentifierFunction is required");
        this.authenticationManager = checkNotNull(authenticationManager, "authenticationManager is required");
        this.authenticationEventPublisher = checkNotNull(authenticationEventPublisher, "authenticationEventPublisher is required");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            Optional<String> optionalSuppliedToken = tokenIdentifierFunction.apply(request);
            if( !optionalSuppliedToken.isPresent() || Strings.isNullOrEmpty(optionalSuppliedToken.get())) {
                throw new BadCredentialsException("Missing authentication token");
            }

            WebAuthenticationDetails details = new WebAuthenticationDetails(request);
            RequestAuthenticationToken requestAuthenticationToken = new RequestAuthenticationToken(optionalSuppliedToken.get(), details);
            Authentication authResult = authenticationManager.authenticate(requestAuthenticationToken);
            if (authResult == null) {
                throw new BadCredentialsException("Null value from authentication manager");
            }
            successfulAuthentication(request, response, authResult);

            filterChain.doFilter(request, response);
        } catch (AuthenticationException failed) {
            unsuccessfulAuthentication(request, response, failed);
        }
    }

    private static void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
        SecurityContextHolder.getContext().setAuthentication(authResult);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        SecurityContextHolder.clearContext();
        if (failed instanceof InternalAuthenticationServiceException) {
            logger.error("An internal error occurred while trying to authenticate the request", failed);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
        authenticationEventPublisher.publishAuthenticationFailure(failed,null);
    }
}
