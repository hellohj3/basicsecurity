package io.security.basicsecurity.security.handler;

import lombok.Setter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Setter
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    // 접근거부 처리 핸들러

    private String errorPage;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // accessDeniedException = 인가예외 객체

        String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
        response.sendRedirect(deniedUrl);
    }
}
