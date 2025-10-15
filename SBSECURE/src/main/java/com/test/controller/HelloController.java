package com.test.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
	
	@GetMapping("/api/user")
	public String userAccess() {
		return "Hello User! you are Authenticated!";
	}
	
	@GetMapping("/api/admin")
	public String adminAccess() {
		return "Hello Admin! you are authenticated!";
	}
}
