package com.example.autenticacion.auth;

import com.example.autenticacion.user.User;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
   private String refreshToken;
   private Long expiresIn;
   private UserProfileResponse user;

    
}
