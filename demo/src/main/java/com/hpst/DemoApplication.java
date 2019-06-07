package com.hpst;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
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
		http.formLogin().and().httpBasic();
		
		http.authorizeRequests()
		.mvcMatchers("/root").hasRole("ROLE_ADMIN")
		.mvcMatchers("/a").access("hasRole('ROLE_ADMIN')")
		.mvcMatchers("/b").access("has");
		
		
		log.info("***************configure http- end*****************");
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		
		log.info("***************configure web -start***************");
		log.info("***************configure web -end*****************");
	}
	


}

@Service
class CustomUserDetailService implements UserDetailsService{

	//In real world app user details will be fetched from a api/service/database etc.
	private final Map<String, UserDetails> detailsMap = new HashMap<>();

	public CustomUserDetailService() {
		this.detailsMap.put("harpal", new CustomUser("harpal", "password", true, "USER"));
		this.detailsMap.put("satveer", new CustomUser("satveer", "password", true, "USER", "ADMIN"));
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if(!this.detailsMap.containsKey(username))
			throw 	new UsernameNotFoundException("can't find "+username);
		return this.detailsMap.get(username);
	}
	
}

class CustomUser implements UserDetails{

	
	private static final long serialVersionUID = 9189229251140054895L;
	private final Set<GrantedAuthority> authorities = new HashSet<>();
	private final String username ;
	private final String password ;
	private final boolean active ;

	public CustomUser(String username, String password, boolean active,String... authorities) {
		this.username= username;
		this.password = password;
		this.active= active;
		this.authorities.addAll(
					Arrays.asList(authorities)
						  .stream()
						  .map(authority-> new SimpleGrantedAuthority("ROLE_"+authority))
						  .collect(Collectors.toSet()));
	}
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.active;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
	
}

@RestController
class AppController{
	
	@GetMapping("/index")
	public String getHome(){
		return "indexs";
	}
}


