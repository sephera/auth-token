package com.example.authtoken.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
                .authorizeRequests().anyRequest().fullyAuthenticated().withObjectPostProcessor(createObjectPostProcessor())
                .and()
                .httpBasic().disable()
                .formLogin().disable()
                .rememberMe().disable()
                .anonymous().disable()
                .logout().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }

    private ObjectPostProcessor<AffirmativeBased> createObjectPostProcessor() {
        return new ObjectPostProcessor<AffirmativeBased>() {

            @Override
            public <O extends AffirmativeBased> O postProcess(O affirmativeBased) {
                affirmativeBased.getDecisionVoters().add(new UriAccessDecisionVoter());
                return affirmativeBased;
            }
        };
    }

    @Autowired
    public void setProvider(TokenAuthenticationProvider provider) {
        this.provider = provider;
    }

}

