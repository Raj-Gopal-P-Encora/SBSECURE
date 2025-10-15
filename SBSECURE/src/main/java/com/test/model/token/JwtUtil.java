package com.test.model.token;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	private static final String SECRET_Key = "my-super-secret-key-that-is-very-strong-123456";
	private static final long EXPIRATION = 1000 * 60 * 60;
	private final Key key = Keys.hmacShaKeyFor(SECRET_Key.getBytes());
	
	public String generateToken(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis()+EXPIRATION))
				.signWith(key,SignatureAlgorithm.HS256)
				.compact();
	}
	
	
	public String extractUsername(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody()
				.getSubject();
	}
	
	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;
		}
		catch(JwtException e) {
			return false;
		}
	}
	
}
