package com.digitalascent.spring.security.token;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface TokenDetails {

    Collection<? extends GrantedAuthority> getAuthorities();

    String getToken();

    boolean isCredentialsNonExpired();

    boolean isEnabled();
}
