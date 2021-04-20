package io.security.basicsecurity.security.common;

import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    // 사용자가 전달하는 username, password 이외의 추가적인 파라매터를 저장하는 클래스
    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretKey = request.getParameter("secret_key");
    }

}
