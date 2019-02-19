package com.digitalascent.spring.security.token;

import com.digitalascent.common.base.StaticUtilityClass;
import com.digitalascent.servlet.HttpRequests;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.Function;

public final class TokenIdentifierExtractors {

    public static Function<HttpServletRequest, Optional<String>> headerValue( String headerName ) {
        return request -> HttpRequests.headerValue(request, headerName );
    }

    private TokenIdentifierExtractors() {
        StaticUtilityClass.throwCannotInstantiateError(getClass());
    }
}
