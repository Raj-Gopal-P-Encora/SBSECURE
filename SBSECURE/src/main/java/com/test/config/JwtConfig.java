package com.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.SecurityFilterChain;

import com.test.token.JwtUtil;

@Configuration
public class JwtConfig {
	
	@Bean
	JwtUtil jwtUtil() {
		return new JwtUtil();
	}
	
	
}
