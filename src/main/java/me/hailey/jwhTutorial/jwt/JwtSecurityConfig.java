package me.hailey.jwhTutorial.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


//TokenProvider, JwtFilter, SecurityConfig에 적용할 때 사용할 JwtSecurityConfig
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

     private TokenProvider tokenProvider;
     public JwtSecurityConfig(TokenProvider tokenProvider) {
         this.tokenProvider = tokenProvider;
     }

    @Override //시큐리티 로직에 필터를 등록
    public void configure(HttpSecurity http)  {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
