package com.example.autenticacion.auth;

import com.example.autenticacion.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {
    private Integer id;
    private String username;
    private String name;
    private String email;
    private Role role;
    private Boolean emailVerified;
    private LocalDateTime createdAt;
}
