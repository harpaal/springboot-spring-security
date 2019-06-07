package com.hpst;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.HttpFirewallBeanDefinitionParser;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}

@Slf4j
@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	
	@Bean
	PasswordEncoder encoder() {
		return NoOpPasswordEncoder.getInstance();
	}
		
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.info("***************configure -start*****************");
		
		auth.inMemoryAuthentication().withUser("hpst").password("hpst").authorities("ADMIN");
		log.info("***************configure - end*****************");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.info("***************configure http-start********* s********");
		http
		.authorizeRequests()
		.antMatchers("/css/**", "/")
		.permitAll()
		.and()
		.formLogin();
		log.info("***************configure http- end*****************");
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		
		log.info("***************configure web -start*****************");
		log.info("***************configure web -end*****************");
	}
	


}



@RestController
class AppController{
	
	@GetMapping("/index")
	public String getHome(){
		return "indexs";
	}
}


