package com.digitalascent.spring.security.token;

import com.digitalascent.common.base.StaticUtilityClass;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.Function;

public final class TokenIdentifierExtractors {

    public static Function<HttpServletRequest, Optional<String>> headerValue( String headerValue ) {
        return request -> Optional.ofNullable(request.getHeader( headerValue ));
    }
    private TokenIdentifierExtractors() {
        StaticUtilityClass.throwCannotInstantiateError(getClass());
    }
}
