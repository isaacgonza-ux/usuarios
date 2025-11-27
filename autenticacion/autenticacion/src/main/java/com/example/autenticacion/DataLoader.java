package com.example.autenticacion;



import com.example.autenticacion.user.User;
import com.example.autenticacion.user.UserRepository;
import com.example.autenticacion.user.Role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.javafaker.Faker;


@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        
        // Solo cargar datos si la tabla está vacía
        if (userRepository.count() > 0) {
            System.out.println("⚠️ Ya existen usuarios en la base de datos. Omitiendo carga inicial.");
            return;
        }
        
        System.out.println("🔵 Iniciando carga de usuarios de prueba...");
        
        Faker faker = new Faker();

        // Crear 1 usuario ADMIN
        try {
            User admin = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin123456"))
                    .name("Administrator")
                    .email("admin@tienda.com")
                    .role(Role.ADMIN)
                    .emailVerified(true)
                    .build();
            
            userRepository.save(admin);
            System.out.println("✅ Usuario ADMIN creado: admin / admin123456");
        } catch (Exception e) {
            System.err.println("❌ Error creando admin: " + e.getMessage());
        }

        // Crear 30 usuarios regulares
        for (int i = 1; i <= 5; i++) {
            try {
                String firstName = faker.name().firstName();
                String lastName = faker.name().lastName();
                String username = firstName.toLowerCase() + i;
                
                User user = User.builder()
                        .username(username)
                        .password(passwordEncoder.encode("password123")) // Misma contraseña para todos
                        .name(firstName + " " + lastName)
                        .email(username + "@email.com")
                        .role(Role.USER)
                        .emailVerified(faker.bool().bool()) // Algunos verificados, otros no
                        .build();
                
                userRepository.save(user);
                
                if (i % 10 == 0) {
                    System.out.println("📊 Usuarios creados: " + i + "/30");
                }
                
            } catch (Exception e) {
                System.err.println("❌ Error creando usuario " + i + ": " + e.getMessage());
            }
        }

        // Mostrar resumen
        long totalUsers = userRepository.count();
        long admins = userRepository.findAll().stream()
                .filter(u -> u.getRole() == Role.ADMIN)
                .count();
        long regularUsers = totalUsers - admins;
        
        System.out.println("===========================================");
        System.out.println("✅ Carga de datos completada");
        System.out.println("📊 Total de usuarios: " + totalUsers);
        System.out.println("👑 Administradores: " + admins);
        System.out.println("👤 Usuarios regulares: " + regularUsers);
        System.out.println("===========================================");
        System.out.println("🔑 Credenciales de prueba:");
        System.out.println("   Admin: admin / admin123456");
        System.out.println("   Users: john1 / password123");
        System.out.println("          mary2 / password123");
        System.out.println("          ... etc");
        System.out.println("===========================================");
    }
}