package com.example.springsecurityjwt.web;

import com.example.springsecurityjwt.dto.AuthenticationRequestDTO;
import com.example.springsecurityjwt.dto.AuthenticationResponseDTO;
import com.example.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;
    @RequestMapping(value = "/hello")
    public String hello()
    {
        return "hello";
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<?> createAutenticationToken(@RequestBody AuthenticationRequestDTO authenticationRequestDTO) throws Exception {
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequestDTO.getUserName() , authenticationRequestDTO.getPassword())
            );
        }catch (BadCredentialsException ex)
        {
            throw new Exception("incorect userName or password",ex);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequestDTO.getUserName());

        String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponseDTO(jwt));
    }
}
