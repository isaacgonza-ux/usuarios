package com.example.autenticacion.auth;

import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;



@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController{

  private final AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request){

    return ResponseEntity.ok(authService.login(request));
  }

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request){

    return ResponseEntity.ok(authService.register(request));
  }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        return ResponseEntity.ok(authService.forgotPassword(request));
    }


     @PostMapping("/reset-password")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        return ResponseEntity.ok(authService.resetPassword(request));
    }


    
    // ============================================
    // ENDPOINTS PROTEGIDOS (requieren autenticación)
    // ============================================

    @GetMapping("/me")
    public ResponseEntity<UserProfileResponse> getCurrentUser() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.getCurrentUser(username));
    }

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.logout(username));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<MessageResponse> logoutAll() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.logoutAll(username));
    }

    @PutMapping("/change-password")
    public ResponseEntity<MessageResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.changePassword(username, request));
    }

    @PutMapping("/profile")
    public ResponseEntity<UserProfileResponse> updateProfile(@Valid @RequestBody UpdateProfileRequest request) {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.updateProfile(username, request));
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<MessageResponse> deleteAccount() {
        String username = getCurrentUsername();
        return ResponseEntity.ok(authService.deleteAccount(username));
    }

    // ============================================
    // MÉTODO AUXILIAR
    // ============================================

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("Usuario no autenticado");
        }
        return authentication.getName();
    }
}



  

