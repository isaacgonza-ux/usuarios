package com.example.autenticacion.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.example.autenticacion.user.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${jwt.secret:XWgEf7xRA6tkom6nODTX0W4GYYq6CnGOyzo+8QtJDnM=}")
    private String SECRET_KEY;

    @Value("${jwt.expiration:3600000}") // 1 hora por defecto
    private Long JWT_EXPIRATION;

    @Value("${jwt.refresh-expiration:604800000}") // 7 días por defecto
    
    private Long REFRESH_EXPIRATION;

     // Access Token (1 hora)
    public String getToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        
        if (userDetails instanceof User) {
            User user = (User) userDetails;
            claims.put("userId", user.getId());
            claims.put("email", user.getEmail());
            claims.put("role", user.getRole().name());
        }
        
        return buildToken(claims, userDetails, JWT_EXPIRATION);
    }

    // Refresh Token (7 días)
    public String getRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        
        if (userDetails instanceof User) {
            User user = (User) userDetails;
            claims.put("userId", user.getId());
            claims.put("type", "refresh");
        }
        
        return buildToken(claims, userDetails, REFRESH_EXPIRATION);
    }

     private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

   

    private Key getKey() {
         try {
            byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
            System.out.println("Clave decodificada correctamente. Bytes: " + keyBytes.length);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            System.err.println("ERROR al decodificar clave: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

     public Integer getUserIdFromToken(String token) {
        return getClaim(token, claims -> claims.get("userId", Integer.class));
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName=getUsernameFromToken(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
        
    }

     public boolean isRefreshToken(String token) {
        try {
            String type = getClaim(token, claims -> claims.get("type", String.class));
            return "refresh".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    private Claims getAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public <T> T getClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);

    }


    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }


    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }

    public Long getExpirationTime() {
        return JWT_EXPIRATION / 1000; // Retorna en segundos
    }


}
