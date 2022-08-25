package com.example.springsecurityjwt.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @AllArgsConstructor @NoArgsConstructor
public class AuthenticationRequestDTO {
    private String userName;
    private String password;
}
