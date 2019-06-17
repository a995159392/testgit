package com.yyhn.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("123").roles("ADMIN","USER","DBA")
                .and()
                .withUser("user").password("123").roles("USER")
                .and()
                .withUser("DBA").password("123").roles("DBA");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/user/**")
                .hasRole("USER")
                .antMatchers("/dba/**")
                .hasRole("DBA")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .usernameParameter("uname")
                .passwordParameter("pwd")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                            Object principal=authentication.getPrincipal();
                            httpServletResponse.setContentType("application/json;charset=utf-8");
                            httpServletResponse.setStatus(200);
                            Map<String,Object> map=new HashMap<>();
                            map.put("status",220);
                            map.put("msg",principal);
                            ObjectMapper om=new ObjectMapper();
                            httpServletResponse.getWriter().write(om.writeValueAsString(map));
                            httpServletResponse.getWriter().flush();
                            httpServletResponse.getWriter().close();
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                       httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter out=httpServletResponse.getWriter();
                        httpServletResponse.setStatus(401);
                        Map<String,Object> map=new HashMap<>();
                        map.put("staus","401");
                        if(e instanceof LockedException)
                            map.put("msg","账号被锁定，登录失败");
                        else if(e instanceof BadCredentialsException)
                            map.put("msg","账号或者密码错误，登录失败");
                        else
                            map.put("msg","登录失败saaa");

                        ObjectMapper obj=new ObjectMapper();
                        out.write(obj.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and()
                .csrf()
                .disable();
    }
}
