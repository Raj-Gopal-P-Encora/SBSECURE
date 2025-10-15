package com.test.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.test.token.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	        throws ServletException, IOException {

	    String header = request.getHeader("Authorization");
	    if (header != null && header.startsWith("Bearer ")) {
	        String token = header.substring(7);
	        try {
	            String username = jwtUtil.extractUsername(token);
	            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
	                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

	                if (jwtUtil.validateToken(token)) {
	                    UsernamePasswordAuthenticationToken authToken =
	                            new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
	                    SecurityContextHolder.getContext().setAuthentication(authToken);
	                }
	            }
	        } catch (Exception e) {
	            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
	            return;
	        }
	    }
	    // ✅ Always forward the request
	    filterChain.doFilter(request, response);
	}

		   
}
	

