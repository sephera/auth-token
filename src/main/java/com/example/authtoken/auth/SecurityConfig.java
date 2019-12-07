package com.example.authtoken.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private TokenAuthenticationProvider provider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(provider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        final TokenAuthenticationFilter filter = new TokenAuthenticationFilter(new TokenAuthenticationEntryPoint(), authenticationManager());
        http.authenticationProvider(provider)
                .addFilterAfter(filter, LogoutFilter.class)
                .httpBasic().disable()
                .formLogin().disable()
                .anonymous().disable()
                .logout().disable()
                .csrf().disable()
                .sessionManagement().disable();
    }
}

