package com.codegym.inote.configuration;

import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    public static final String CHECKED_USER_ID = "@webSecurity.checkUserId(authentication,#userId)";
    public static final String LOGIN = "/login";

    @Autowired
    private CustomSuccessHandler customSuccessHandler;

    @Autowired
    private UserService userService;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public RestAuthenticationEntryPoint restServicesEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    @Bean
    public CustomAccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public WebSecurity webSecurity() {
        return new WebSecurity();
    }

    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().ignoringAntMatchers("/restful/**");
        http.httpBasic().authenticationEntryPoint(restServicesEntryPoint());
        http.authorizeRequests()
                .antMatchers("/homepage",
                        LOGIN,
                        "/register",
                        "/restful/register",
                        "/restful/login",
                        "/confirm-account/**",
                        "/forgotPassword",
                        "/forgotPassword?success/**",
                        "/newPassword/**",
                        "/sendOTP",
                        "/verifyOTPSuccess",
                        "/login-facebook/**").permitAll()
                .antMatchers("/note/notes/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/note/create/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/note/edit/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/note/delete/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/note/view/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/noteType/noteTypeList/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/noteType/create/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/noteType/edit/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/noteType/delete/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/noteType/view/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/tag/tags/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/tag/create/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/tag/edit/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/tag/delete/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/tag/view/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/stack/create/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/stack/edit/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/stack/delete/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers("/stack/view/{id}/{userId}/**").
                access(CHECKED_USER_ID).
                antMatchers("/stack/stacks/{id}/{userId}/**").
                access(CHECKED_USER_ID)
                .antMatchers(HttpMethod.GET, "/restful/users").
                access("hasRole('ROLE_ADMIN')")
                .antMatchers("/restful/**").access("hasRole('ROLE_USER')")
                .anyRequest().authenticated()
                .and().formLogin().loginPage(LOGIN).permitAll().loginProcessingUrl(LOGIN).successHandler(this.customSuccessHandler)
                .usernameParameter("username").passwordParameter("password")
                .and().csrf()
                .and().exceptionHandling().accessDeniedPage("/Access_Denied")
                .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling().accessDeniedHandler(customAccessDeniedHandler());
    }
}
