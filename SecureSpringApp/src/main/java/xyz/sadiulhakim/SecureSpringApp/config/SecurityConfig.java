package xyz.sadiulhakim.SecureSpringApp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain config(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .userDetailsService(userDetailsService())
                .oauth2Login(login -> login.loginPage("/oauth2/authorization/google"))
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
                .build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails hakim = User.withUsername("hakim")
                .password(passwordEncoder().encode("hakim@123"))
                .roles("ADMIN")
                .build();
        UserDetails ashik = User.withUsername("ashik")
                .password(passwordEncoder().encode("hakim@123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(hakim, ashik);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
