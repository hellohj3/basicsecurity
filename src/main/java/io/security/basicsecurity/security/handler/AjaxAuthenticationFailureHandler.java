package io.security.basicsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

    // 로그인 실패정보를 response 에 담아 전달

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invalid Username or Password";

        if (exception instanceof DisabledException) {
            errorMessage = "Locked";
        } else if (exception instanceof DisabledException) {
            errorMessage = "Expired password";
        }

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getWriter(), errorMessage);
    }
}
