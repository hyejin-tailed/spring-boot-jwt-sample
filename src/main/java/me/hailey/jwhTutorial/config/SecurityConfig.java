package me.hailey.jwhTutorial.config;

import me.hailey.jwhTutorial.jwt.JwtAccessDeniedHandler;
import me.hailey.jwhTutorial.jwt.JwtAuthenticationEntryPoint;
import me.hailey.jwhTutorial.jwt.JwtSecurityConfig;
import me.hailey.jwhTutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        //h2-console 하위 요청과 파비콘 관련 요청은 Spring Security로직을 수행하지 않음
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable() //토큰을 사용하기 때문에 csrf 설정은 disable

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //h2-console을 위한 설정
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                //이 프로젝트에선 세션을 쓰지 않음
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //토큰이 없는 상태에서 요청이 들어오는 경우 고려
                .and()
                .authorizeRequests() //HttpServletRequest를 사용하는 요청들에 대한 접근제한 설정
                .antMatchers("api/hello").permitAll() //인 없이 허용하겠다.
                .antMatchers("api/aauthenticate").permitAll()
                .antMatchers("api/signup").permitAll()
                .anyRequest().authenticated()//이  요청은 인증 없이 허용하겠다.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}
