package com.personal.api.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.http.HttpMethod;


@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
	
	private Environment environment;

	@Autowired
	public WebSecurity(Environment environment)
	{
		this.environment = environment;
	}
	
	@Override
	protected void configure(HttpSecurity http)throws Exception{
		
		//we are using JWT Token for user authorization so disabled csrf
		http.csrf().disable();
		http.headers().frameOptions().disable(); // i put it here to access h2 database console.  
    	http.authorizeRequests()
    	.antMatchers(HttpMethod.POST, environment.getProperty("api.registration.url.path")).permitAll()
    	.antMatchers(HttpMethod.POST, environment.getProperty("api.login.url.path")).permitAll()
    	.antMatchers(environment.getProperty("api.users.actuator.url.path")).permitAll()  // health bean  status and so on
    	.antMatchers(environment.getProperty("api.account.actuator.url.path")).permitAll()
    	.antMatchers(environment.getProperty("api.zuul.actuator.url.path")).permitAll()
    	.antMatchers(environment.getProperty("api.h2console.url.path")).permitAll()
    	.anyRequest().authenticated()
    	.and()
    	.addFilter(new AuthorizationFilter(authenticationManager(), environment));
    	
    	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //stateless  for rest api. spring jsp  stateful we can make next time you dont need to authorize
    	
	}

}