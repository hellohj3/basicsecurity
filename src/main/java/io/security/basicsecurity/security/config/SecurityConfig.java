package io.security.basicsecurity.security.config;

import io.security.basicsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.basicsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.basicsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.security.basicsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.basicsecurity.security.provider.CustomAuthenticationProvider;
import io.security.basicsecurity.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 폼 로그인 관련 설정 클래스
 *
 * @author 박상재
 * @version 1.0
 */
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // private final CustomUserDetailsService userDetailsService;
    private final FormAuthenticationDetailsSource authenticationDetailsSource;
    private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler authenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomAuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 커스텀 UserDetailsService 등록
        // auth.userDetailsService(userDetailsService);         // CustomAuthenticationProvider 에서 CustomUserDetailsService 를 사용하므로 삭제
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 정적파일 보안필터 제외
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 폼로그인 및 자원에 대한 접근제한 설정
        http
                .authorizeRequests()
                .antMatchers("/","/users","/login**").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()
            .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());

        // Cross Site Request Forgery 관련기능 비활성화
        http.csrf().disable();
    }
}
