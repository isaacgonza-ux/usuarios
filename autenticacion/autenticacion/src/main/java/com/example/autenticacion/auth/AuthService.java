package com.example.autenticacion.auth;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.sql.Delete;
import org.springframework.boot.autoconfigure.couchbase.CouchbaseProperties.Authentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.autenticacion.user.UserRepository;

import jakarta.transaction.Transactional;

import com.example.autenticacion.user.User;
import com.example.autenticacion.AutenticacionApplication;
import com.example.autenticacion.jwt.JwtService;
import com.example.autenticacion.user.PasswordResetToken;
import com.example.autenticacion.user.PasswordResetTokenRepository;
import com.example.autenticacion.user.RefreshToken;
import com.example.autenticacion.user.RefreshTokenRepository;
import com.example.autenticacion.user.Role;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
   
    @Transactional
    public AuthResponse login(LoginRequest request) {
        
         // Autenticar
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

          // Obtener usuario
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email no encontrado"));

        // Generar tokens
        String accessToken = jwtService.getToken(user);
        String refreshToken = jwtService.getRefreshToken(user);

        
        // Guardar refresh token en BD
        saveRefreshToken(user, refreshToken);

        return buildAuthResponse(user, accessToken, refreshToken);



    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        
             // Validar que username y email no existan
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("El username ya existe");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("El email ya está registrado");
        }

        // Crear usuario
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .email(request.getEmail())
                .role(Role.USER) // Por defecto USER, no ADMIN
                .emailVerified(false)
                .build();

        userRepository.save(user);

        // Generar tokens
        String accessToken = jwtService.getToken(user);
        String refreshToken = jwtService.getRefreshToken(user);

        // Guardar refresh token
        saveRefreshToken(user, refreshToken);

        // TODO: Enviar email de verificación
        // emailService.sendVerificationEmail(user);

        return buildAuthResponse(user, accessToken, refreshToken);
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // Validar que sea refresh token
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new RuntimeException("Token inválido");
        }

        // Obtener username del token
        String username = jwtService.getUsernameFromToken(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Validar refresh token en BD
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token no encontrado"));

        if (storedToken.getRevoked() || storedToken.isExpired()) {
            throw new RuntimeException("Refresh token inválido o expirado");
        }

        // Generar nuevo access token
        String newAccessToken = jwtService.getToken(user);

        return AuthResponse.builder()
                .token(newAccessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getExpirationTime())
                .user(mapToUserProfile(user))
                .build();
    }


     @Transactional
    public MessageResponse logout(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Revocar todos los refresh tokens del usuario
        refreshTokenRepository.findByUser(user).forEach(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });

        return MessageResponse.builder()
                .success(true)
                .message("Sesión cerrada exitosamente")
                .build();
    }


     @Transactional
    public MessageResponse logoutAll(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Eliminar todos los refresh tokens
        refreshTokenRepository.deleteByUser(user);

        return MessageResponse.builder()
                .success(true)
                .message("Todas las sesiones cerradas exitosamente")
                .build();
    }


      @Transactional
    public MessageResponse forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElse(null);

        // Por seguridad, siempre responder lo mismo aunque el email no exista
        if (user != null) {
            // Generar token único
            String token = UUID.randomUUID().toString();

            // Guardar token en BD (válido por 1 hora)
            PasswordResetToken resetToken = PasswordResetToken.builder()
                    .token(token)
                    .user(user)
                    .expiresAt(LocalDateTime.now().plusHours(1))
                    .build();

            passwordResetTokenRepository.save(resetToken);

            // TODO: Enviar email con el link
            // emailService.sendPasswordResetEmail(user.getEmail(), token);
        }

        return MessageResponse.builder()
                .success(true)
                .message("Si el correo existe, recibirás un link de recuperación")
                .build();
    }

    @Transactional
    public MessageResponse resetPassword(ResetPasswordRequest request) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Token inválido"));

        if (resetToken.getUsed() || resetToken.isExpired()) {
            throw new RuntimeException("Token expirado o ya utilizado");
        }

        // Actualizar contraseña
        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Marcar token como usado
        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);

        // Revocar todos los refresh tokens (cerrar todas las sesiones)
        refreshTokenRepository.deleteByUser(user);

        return MessageResponse.builder()
                .success(true)
                .message("Contraseña actualizada exitosamente")
                .build();
    }


      @Transactional
    public MessageResponse changePassword(String username, ChangePasswordRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Verificar contraseña actual
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new RuntimeException("Contraseña actual incorrecta");
        }

        // Actualizar contraseña
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        return MessageResponse.builder()
                .success(true)
                .message("Contraseña cambiada exitosamente")
                .build();
    }

    public UserProfileResponse getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        
        return mapToUserProfile(user);
    }

    @Transactional
    public UserProfileResponse updateProfile(String username, UpdateProfileRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Actualizar campos
        if (request.getName() != null && !request.getName().isEmpty()) {
            user.setName(request.getName());
        }

        if (request.getUsername() != null && !request.getUsername().isEmpty()) {
            // Verificar que el nuevo username no exista
            if (!request.getUsername().equals(username) && 
                userRepository.existsByUsername(request.getUsername())) {
                throw new RuntimeException("El username ya existe");
            }
            user.setUsername(request.getUsername());
        }

        userRepository.save(user);
        return mapToUserProfile(user);
    }
    
        @Transactional
        public MessageResponse deleteAccount(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        //. Borrar tokens asociados al usuario
        refreshTokenRepository.deleteByUser(user);
        passwordResetTokenRepository.deleteByUser(user);
        // Eliminar usuario
        userRepository.delete(user);
        return MessageResponse.builder()
                .success(true)
                .message("Cuenta eliminada exitosamente")
                .build();
    }
    
    // ============================================
    // MÉTODOS AUXILIARES
    // ============================================

    private void saveRefreshToken(User user, String tokenString) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenString)
                .user(user)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    private AuthResponse buildAuthResponse(User user, String accessToken, String refreshToken) {
        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getExpirationTime())
                .user(mapToUserProfile(user))
                .build();
    }

    private UserProfileResponse mapToUserProfile(User user) {
        return UserProfileResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole())
                .emailVerified(user.getEmailVerified())
                .createdAt(user.getCreatedAt())
                .build();
    }




    

}
