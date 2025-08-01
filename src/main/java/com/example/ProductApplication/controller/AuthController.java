package com.example.ProductApplication.controller;

import com.example.ProductApplication.entity.User;
import com.example.ProductApplication.security.JwtUtil;
import com.example.ProductApplication.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/register")
public String register(@RequestBody User user) {
    // Accepts "role" as part of the JSON body
    String role = user.getRoles().iterator().next().getName(); // extract first role name
    userService.registerUser(user.getUsername(), user.getPassword(), role);
    return "User registered successfully with role: " + role;
}

   @PostMapping("/login")
public String login(@RequestBody User user) {
    try {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        final String jwt = jwtUtil.generateToken(user, userDetails);
        System.out.println("Generated JWT: " + jwt);  // Add this line for debugging
        return jwt;
    } catch (Exception e) {
        e.printStackTrace();
        return "Login failed: " + e.getMessage();
    }
    
}

}
