package com.digitalascent.spring.security.token;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;


public class RequestTokenAuthenticationFilterTest {

    private Filter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;
    private WebAuthenticationDetails authenticationDetails;

    @Before
    public void setup() {
        AuthenticationManager authenticationManager = Mockito.mock(AuthenticationManager.class);
        filter = new RequestTokenAuthenticationFilter(TokenIdentifierExtractors.headerValue("x-api-key"), authenticationManager, new DefaultAuthenticationEventPublisher() );
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
        authenticationDetails = new WebAuthenticationDetails( request );
        Mockito.when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(new AuthenticatedRequestAuthenticationToken(ImmutableList.of(),"",authenticationDetails));
    }

    @Test
    public void testAuthSucceeds() throws IOException, ServletException {

        request.addHeader("x-api-key", "12345");
        filter.doFilter(request,response,filterChain);
        assertThat( response.getStatus() ).isEqualTo( 200 );
        assertThat( SecurityContextHolder.getContext().getAuthentication().getDetails() ).isEqualTo(authenticationDetails);
    }

    @Test
    public void testMissingApiKeyFails() throws IOException, ServletException {
        filter.doFilter(request,response,filterChain);
        assertThat( response.getStatus() ).isEqualTo( 403 );
        assertThat( SecurityContextHolder.getContext().getAuthentication() ).isNull();
    }
}