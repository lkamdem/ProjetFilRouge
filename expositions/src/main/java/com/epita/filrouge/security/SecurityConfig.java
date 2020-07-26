package com.epita.filrouge.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.GsonBuilderUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, proxyTargetClass = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailServiceImpl;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailServiceImpl).passwordEncoder(passwordEncoder());
        System.out.println("******* AUTHENTIFICATION ********");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/logout").permitAll()
                .antMatchers("/gestaffectation/**").authenticated().anyRequest().permitAll()
//                .antMatchers("/gestaffectation/**").permitAll()
            .and()
            .formLogin()
                .loginProcessingUrl("/login")
                .successHandler(new AuthentificationLoginSuccessHandler())
                .failureHandler(new SimpleUrlAuthenticationFailureHandler())
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new AuthentificationLogoutSuccessHandler())
                .invalidateHttpSession(true)
            .and()
            .exceptionHandling().authenticationEntryPoint(new Http403ForbiddenEntryPoint() {});
    }

    private class AuthentificationLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                            final Authentication authentication) throws IOException, ServletException {
            response.setStatus(HttpServletResponse.SC_OK);
        }
    }

    private class AuthentificationLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                    final Authentication authentication) throws IOException, ServletException {
            response.setStatus(HttpServletResponse.SC_OK);
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}