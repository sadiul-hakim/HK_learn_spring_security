# `SecureSpringApp`

We have very secret information in index.html file. We want to hide it. In a monolith backend app we can secure
our application in many ways. Like:

1. Form Login
2. Basic Auth
3. Social Login (OAuth2)
4. Oauth2 with third parties like (KeyCloak,Okta)

## Configure User and UserDetailsService in your system

1. Create a User Entity and save some users in your database. User must have some columns like
   id,email,password,role/authorities and create UserRepository
2. Create another class and implement UserDetails Overwrite getUsername() `which is normaly email`, getPassword() and
   getAuthorities() suppose `CustomeUserDetails`
3. Create a class that implements UserDetailsService and Overrides loadUserByUsername() that returns an instance of
   `CustomeUserDetails` suppose `CustomeUserDetailsService`
4. Create a `@Bean` of PasswordEncoder `Normally it is BCryptPasswordEncoder`
5. Now we have to add and instance of `CustomeUserDetailsService` in `.userDetailsService()` of HttpSecurity. No need to
   put any instance of PasswordEncoder anywhere if there is only one Bean of PasswordEncoder.

`If we do not have real users we can create some HardCoded users in our system. Like below:`

```java

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
```

`Now just add this UserDetailsService to HttpSecurity.`

## Authorization

`For authorization we can use .authorizeHttpRequests() of HttpSecurity class. Also we have options for Method level 
security. While using HttpSecurity class for Authorization (1) First we should pass the permitAll endpoints (2) Then 
endpoints with roles or authorities and then (3) endpoints with only authenticated access. Like below:`

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {

    String[] publicApi = {
            "/",
            "/css/**",
            "/fonts/**",
            "/js/**",
            "/images/**",
            "/picture/**",
            "/admin_login"
    };

    String[] authenticatedUserAccess = {
            "/categories/get-all",
            "/brands/get-all",
            "/products/get-all"
    };

    String[] adminAccess = {
            "/dashboard/**",
            "/users/**",
            "/roles/**",
            "/brands/**",
            "/categories/**",
            "/products/**"
    };
    return http
            .authorizeHttpRequests(auth -> auth.requestMatchers(publicApi).permitAll())
            .authorizeHttpRequests(auth -> auth.requestMatchers(authenticatedUserAccess).authenticated())
            .authorizeHttpRequests(auth -> auth.requestMatchers(adminAccess).hasAnyRole("ADMIN", "ASSISTANT"))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .userDetailsService(userDetailsService)
            .oauth2Login(login -> login.loginPage("/oauth2/authorization/google").successHandler(authenticationSuccessHandler))
            .formLogin(form -> form
                    .loginPage("/admin_login")
                    .defaultSuccessUrl("/dashboard/page", true)
                    .loginProcessingUrl("/login")
                    .failureUrl("/login?error=true").permitAll())
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}
```

## CORS

> Create Bean

```java

@Bean
public CorsConfigurationSource corsConfigurationSource() {

    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(List.of("*"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setMaxAge(3600L);
    configuration.setAllowedHeaders(List.of(
            "Authorization", "Content-Type", "X-Requested-With", "Origin", "Accept",
            "Access-Control-Request-Method", "Access-Control-Request-Headers"
    ));
    configuration.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
}
```

> Add this to HttpSecurity

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {
    return http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}
```

## CSRF Security

`CSRF is by default inabled by spring security. In case of Form Login we can access csrf using _csrf parameter. We can 
customize csrf security.`

### 1️⃣ Default CSRF Configuration (Enabled)

Spring Security enables **CSRF protection by default**. If you don’t configure anything, it is already protecting
against CSRF attacks.

#### How CSRF Protection Works

1. **Spring Security generates a CSRF token**.
2. **The token is included in HTML forms as a hidden field**.
3. **For non-GET requests (POST, PUT, DELETE, PATCH), Spring Security validates the token**.
4. **If the token is missing or incorrect, the request is rejected**.

---

### 2️⃣ Customizing CSRF Configuration

By default, Spring Security applies CSRF protection to all endpoints. You can customize it using `SecurityFilterChain`.

#### 2.1 CSRF Configuration with Custom Request Matcher

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf
                    .ignoringRequestMatchers("/api/public/**") // Disable CSRF for public API
            )
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
    return http.build();
}
```

✅ CSRF is enabled, but requests to `/api/public/**` will not require a CSRF token.

---

#### 2.2 CSRF Configuration for REST APIs (Stateless JWT Authentication)

For **stateless REST APIs**, you usually **disable CSRF** because:

- APIs don’t use **cookies-based authentication**.
- APIs rely on **JWT or OAuth tokens**.

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for stateless APIs
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/**").permitAll()
                    .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    return http.build();
}
```

✅ CSRF is disabled for REST APIs using JWT authentication.

---

#### 2.3 Enabling CSRF Token in Headers (AJAX & SPAs)

For **AJAX requests or Single Page Applications (SPAs)**:

##### Frontend - Sending CSRF Token in AJAX Request

```javascript
fetch('/api/protected', {
    method: 'POST',
    headers: {
        'X-XSRF-TOKEN': getCsrfToken(), // Retrieve CSRF token from cookies
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({name: "example"})
});
```

##### Spring Security - Configuring CSRF Token in Headers

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Store CSRF token in cookies
            )
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
            )
            .formLogin(Customizer.withDefaults());
    return http.build();
}
```

✅ The CSRF token will be stored in a cookie named **`XSRF-TOKEN`**, and the frontend must send it as **`X-XSRF-TOKEN`**.

---

### 3️⃣ Advanced CSRF Configurations

#### 3.1 CSRF Token Repository (Custom Implementation)

```java

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(csrf -> csrf
                    .csrfTokenRepository(new CustomCsrfTokenRepository()) // Use custom CSRF repository
                     .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/admin/**").authenticated()
                    .anyRequest().permitAll()
            )
            .formLogin(Customizer.withDefaults());
    return http.build();
}
```

**Custom CsrfTokenRepository Example:**

```java
public class CustomCsrfTokenRepository implements CsrfTokenRepository {

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String token = UUID.randomUUID().toString();
        return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", token);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        if (token != null) {
            response.setHeader("X-CSRF-TOKEN", token.getToken());
        }
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        String token = request.getHeader("X-CSRF-TOKEN");
        return token != null ? new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", token) : null;
    }
}
```

✅ Custom token repository that stores CSRF tokens in HTTP headers.

---

### 4️⃣ When to Enable or Disable CSRF?

| **Scenario**                    | **Enable CSRF?** | **Reason**                           |
|---------------------------------|------------------|--------------------------------------|
| Traditional Web Apps (Forms)    | ✅ Yes            | Uses session-based authentication    |
| REST APIs (JWT/OAuth)           | ❌ No             | Stateless authentication, no session |
| AJAX Requests (SPAs)            | ✅ Yes            | Uses cookies for authentication      |
| Public APIs (No Authentication) | ❌ No             | No sensitive state changes           |

### 5️⃣ Conclusion

- **CSRF is enabled by default** in Spring Security.
- **Disable CSRF for stateless REST APIs** (e.g., JWT-based authentication).
- **Use `CookieCsrfTokenRepository` for AJAX-based apps**.
- **Customize CSRF handling using `CsrfTokenRepository`** for advanced use cases.

---

## 1. Social Login (OAuth2) - Google

1. Create google app from https://console.cloud.google.com/ use redirect url like this
   `http://localhost:9090/login/oauth2/code/google`
2. Bring Client ID and Secret, put them in environment variables or somewhere safe and do not push them in GitHub
3. Add `spring-boot-starter-oauth2-client` dependency in your project
4. Add `spring.security.oauth2.client.registration.google.client-id=${CLIENT_ID}` and
   `spring.security.oauth2.client.registration.google.client-secret=${SECRET}` in properties file.
5. Configure the security in `@Configuration` file like below code
6. access `/oauth2/authorization/google` to login

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2Login(login -> login.loginPage("/oauth2/authorization/google"))
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}
```

`Oauth2 authenticated users Principal type is OAuth2User`

## 2. Basic Auth

We have en endpoint /who_is_he?shortName=?. To secure this app with basic auth follow the next instruction

1. Make sure you have `spring-boot-starter-security` dependency
2. Now we have to add users to our system. We can add hard coded users in our system.
    1. Put user information in properties file add `spring.security.user.name=` and `spring.security.user.password=`
    2. Hardcoded users in `@Configuration` file
    3. Actual users from database.
3. Then put below configuration in `@Configuration` file

with hard coded user in properties file

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}
```

or with real users

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .userDetailsService(userDetailsService)
            .httpBasic(Customizer.withDefaults())
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

`You can provide lamda (http) -> {} and provide some custome configuration`.

## 3. Form Login

`Exactly like Basic Auth with slidly different config like below: `

```java

@Bean
public SecurityFilterChain config(HttpSecurity http) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .userDetailsService(userDetailsService)
            .formLogin(form -> form
                    .loginPage("/admin_login")
                    .defaultSuccessUrl("/dashboard/page", true)
                    .loginProcessingUrl("/login")
                    .failureUrl("/login?error=true").permitAll())
            .logout(logout -> logout.logoutUrl("/logout").permitAll().logoutSuccessUrl("/"))
            .build();
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

`We can create custom login page the login page url should be configured in .loginPage(). We can also change 
username,password, remember_me input fields name.`

## 4. Custom Jwt Authentication
`Custom Jwt Authentication` is the best way to handle authentication for single service backend apps. 
This functionality is not build in the framework, it it done manualy using jwt libraries.

### Dependencies
```xml
<dependencies>
    <!-- Spring Boot Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-impl -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
        <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-jackson -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
</dependencies>
```

### Jwt Helper
```Java
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

public class JwtHelper {
    private static final String SECRET = "VxRfBGJFviiO62cg/M0YY5WypcyvtUUjfkI5aDJgwt4dLz6BQKuaKChKyn+Ulhz+";


    public static String generateToken(UserDetails userDetails, Map<String, Object> extraClaims, long expirationDate) {

        return Jwts.builder()
                .setClaims(extraClaims)
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + expirationDate))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setSubject(userDetails.getUsername())
                .compact();
    }

    public static boolean isValidToken(String token, UserDetails details) throws MalformedJwtException {

        boolean isValid = extractUsername(token).equalsIgnoreCase(details.getUsername()) && !isExpired(token);
        if (!isValid) {
            throw new MalformedJwtException("Invalid Token");
        }
        return true;
    }

    private static boolean isExpired(String token) {

        return extractExpiration(token).before(new Date());
    }

    private static Date extractExpiration(String token) throws MalformedJwtException {

        return parseSingleClaim(token, Claims::getExpiration);
    }

    public static String extractUsername(String token) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, IllegalArgumentException {

        return parseSingleClaim(token, Claims::getSubject);
    }

    public static Object extractClaim(String token, String claim) throws MalformedJwtException {

        return parseSingleClaim(token, claims -> claims.get(claim, Object.class));
    }

    private static <T> T parseSingleClaim(String token, Function<Claims, T> resolver) throws ExpiredJwtException,
            UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {

        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private static Claims extractAllClaims(String token) throws ExpiredJwtException, UnsupportedJwtException,
            MalformedJwtException, SignatureException, IllegalArgumentException {

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getSecretKey()).build();
        return parser.parseClaimsJws(token).getBody();
    }

    private static Key getSecretKey() {

        byte[] bytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(bytes);
    }
}
```

### Authentication Filter
This includes login functionality

```Java
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import xyz.sadiulhakim.util.ResponseUtility;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationProvider authenticationProvider;

    public CustomAuthenticationFilter(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        // Extract the username and password from request attribute
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Create instance of UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // Authenticate the user
        return authenticationProvider.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // Extract the authenticated user.
        var user = (User) authentication.getPrincipal();

        // Generate access and refresh tokens
        // Access token has all the authority information while refresh token does not.
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("roles", user.getAuthorities());

        String accessToken = JwtHelper.generateToken(user, extraClaims, (1000L * 60 * 60 * 24 * 7)); // expires in 7 days
        String refreshToken = JwtHelper.generateToken(user, extraClaims ,(1000L * 60 * 60 * 24 * 30)); // expires in 30 days

        Map<String, String> tokenMap = new HashMap<>();
        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);

        ResponseUtility.commitResponse(response, tokenMap, 200);
    }
}

```

### Authorization Filter
```Java

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.massmanagement.service.CustomUserDetailsService;
import org.massmanagement.util.JwtHelper;
import org.massmanagement.util.ResponseUtility;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {

        try {
            if (request.getServletPath().equalsIgnoreCase("/login") ||
                    request.getServletPath().endsWith("/validate-token")) {
                filterChain.doFilter(request, response);
            } else {
                String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
                if (authorization != null && authorization.startsWith("Bearer ")) {

                    // Extract the token from authorization text
                    String token = authorization.substring("Bearer ".length());

                    // Extract the username
                    String username = JwtHelper.extractUsername(token);

                    // Get the userDetails using username
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                    // If the token is valid and user is not authenticated, authenticate the user
                    if (JwtHelper.isValidToken(token, userDetails) && SecurityContextHolder.getContext().getAuthentication() == null) {
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities() // We need to pass the Granted Authority list, otherwise user would be forbidden.
                        );
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }

                }

                // If the authorization does not exist, or it does not start with Bearer, simply let the program go.
                filterChain.doFilter(request, response);
            }
        } catch (Exception ex) {
            log.error("Error Occurred in CustomAuthorizationFilter. Cause : {}", ex.getMessage());

            // If the token is Invalid send an error with the response
            Map<String, String> errorMap = new HashMap<>();
            errorMap.put("error", ex.getMessage());
            ResponseUtility.commitResponse(response, errorMap, 500);
        }
    }
}
```

### Security Config
```Java
import lombok.RequiredArgsConstructor;
import org.massmanagement.security.CustomAuthenticationFilter;
import org.massmanagement.security.CustomAuthorizationFilter;
import org.massmanagement.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableCaching
@RequiredArgsConstructor
@EnableWebSecurity
class SecurityConfig {
    private final CustomUserDetailsService userDetailsService;
    private final CustomAuthorizationFilter customAuthorizationFilter;
    @Value("${frontend.uri}")
    private String frontendUri;

    @Bean
    public SecurityFilterChain config(HttpSecurity http) throws Exception {


        return http.csrf(csrf -> csrf
                        .ignoringRequestMatchers("/login", "/", "/refreshToken")
                        .csrfTokenRepository(new CustomCsrfTokenRepository())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                )
                .cors(c -> {
                    CorsConfigurationSource source = e -> {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(List.of(frontendUri));
                        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
                        config.setAllowedHeaders(List.of("*"));

                        return config;
                    };

                    c.configurationSource(source);
                })
                .authorizeHttpRequests(auth -> auth.requestMatchers("/security/v1/validate-token").permitAll())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .authenticationProvider(authenticationProvider())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilter(new CustomAuthenticationFilter(authenticationProvider))
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   @Bean
    UserDetailsService userDetailsService() {
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();

        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("user"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder,
                                                     UserDetailsService userDetailsService) {
        var provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
```
---
# OAuth2 in Spring Boot: Explained Simply

OAuth2 is a security framework used for authentication and authorization in modern applications. Spring Boot provides
different components to implement OAuth2:

- **OAuth2 Client**
- **OAuth2 Resource Server**
- **OAuth2 Authorization Server**

This document explains each in simple terms.

---

## 1. **Spring OAuth2 Components**

### **1.1 OAuth2 Client**

- Used when your application needs to **log in users** via **Google, Facebook, GitHub, Keycloak, etc.**
- It **redirects** users to an OAuth2 provider for login.
- Once authenticated, the provider sends an **access token** back to your app.
- Example: Logging in with Google in a web or mobile app.

📌 **Use case:** Frontend or backend applications that authenticate users via an external identity provider.

#### **Example of OAuth2 Client in Spring Boot**

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2Login(); // Enables OAuth2 login (Google, GitHub, etc.)
        return http.build();
    }
}
```

### **1.2 OAuth2 Resource Server**

- Used when your **backend API needs to verify JWT tokens** sent by a client.
- It checks whether a request has a valid token before processing it.
- Example: A mobile app sends a token, and the backend verifies it before giving access to data.

📌 **Use case:** Backend API that protects routes using JWT tokens issued by an Authorization Server.

#### **Example of OAuth2 Resource Server in Spring Boot**

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // Validates JWT tokens
        return http.build();
    }
}
```

### **1.3 OAuth2 Authorization Server**

- Issues **JWT tokens** when users log in.
- Manages **user authentication** and **client (app) authentication**.
- Example: Keycloak, Auth0, Okta, or a self-hosted Spring Authorization Server.

📌 **Use case:** When you need to **issue tokens** for users or apps yourself instead of using an external provider.

#### **Example of OAuth2 Authorization Server in Spring Boot**

```java

@Configuration
public class AuthorizationServerConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http.apply(authorizationServerConfigurer);
        return http.build();
    }
}
```

---

## 2. **Spring Authorization Server vs Keycloak**

| Feature                   | Spring Authorization Server                                 | Keycloak                                         |
|---------------------------|-------------------------------------------------------------|--------------------------------------------------|
| **Purpose**               | Self-hosted OAuth2 Authorization Server for issuing tokens  | Full Identity & Access Management System         |
| **Setup**                 | Requires manual configuration & coding                      | Ready-to-use with UI & Admin Panel               |
| **User Management**       | No built-in user management (you must integrate a database) | Built-in user management, roles, and permissions |
| **Multi-Tenancy**         | Not supported out of the box                                | Supported (multi-realm system)                   |
| **OIDC Support**          | Yes (requires setup)                                        | Yes (pre-configured)                             |
| **Custom Token Handling** | Fully customizable                                          | Customizable but follows Keycloak standards      |
| **Use Case**              | When you need to build a custom token server for APIs       | When you need a full-fledged identity system     |

---

## 3. **Which One Should You Use?**

### ✅ Use **Spring Authorization Server** if:

- You need a **lightweight, custom OAuth2 server**.
- You want **full control over token generation and user authentication**.
- Your project requires a **microservices-friendly** solution.

### ✅ Use **Keycloak** if:

- You need a **ready-made identity provider** with **user management**.
- You don’t want to manually **handle authentication, roles, and permissions**.
- You want features like **multi-tenancy, social login, and federated identity**.

---

## **Conclusion**

- **OAuth2 Client** → For logging in users via Google, GitHub, etc.
- **OAuth2 Resource Server** → For protecting APIs using JWT tokens.
- **OAuth2 Authorization Server** → For issuing JWT tokens.
- **Spring Authorization Server vs Keycloak** → Use Spring if you need full customization; use Keycloak if you need an
  out-of-the-box identity system.

# Securing a Monolithic Spring Boot REST API using Spring OAuth2

This guide explains how to secure a **single-service (monolith) Spring Boot REST API** using **Spring Security with
OAuth2**.

## **1. Dependencies**

Add the following dependencies in your `pom.xml` (Maven):

```xml

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

If you're using **Spring Authorization Server** to issue tokens, add:

```xml

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
</dependency>
```

---

## **2. Configuration**

### **2.1 Configure Authorization Server (Token Issuance using JWT)**

Create `AuthorizationServerConfig.java`:

```java

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-id")
                .clientSecret("{noop}client-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }
}
```

This configuration:

- Sets up an OAuth2 Authorization Server to issue JWT tokens.
- Registers a sample client with `client-id` and `client-secret`.
- Supports `client_credentials` and `password` grant types.

### **2.2 Configure Resource Server (API Protection using JWT)**

Create `SecurityConfig.java`:

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public").permitAll()  // Public endpoints
                        .requestMatchers("/api/user").hasRole("USER")  // Restricted to USER role
                        .requestMatchers("/api/admin").hasRole("ADMIN")  // Restricted to ADMIN role
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);  // Enable JWT validation

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://localhost:9000"); // Use local Authorization Server
    }
}
```

### **2.3 Define Application Properties**

Add OAuth2 configuration in `application.yml`:

```yaml
server:
  port: 9000  # Authorization Server runs separately

spring:
  security:
    oauth2:
      authorization-server:
        issuer: http://localhost:9000
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9000  # Authorization Server URL
```

---

## **3. Flow: How Authentication and Authorization Work**

### **3.1 Authentication Flow**

1. **User logs in** via Spring Authorization Server.
2. The Authorization Server **issues a JWT token** to the user.
3. The user includes the JWT token in the `Authorization` header when making requests to the API:
   ```http
   GET /api/user HTTP/1.1
   Host: myapi.com
   Authorization: Bearer eyJhbGciOiJIUzI1...
   ```
4. Spring Boot **validates the JWT token** using the Authorization Server (`http://localhost:9000`).
5. If the token is valid, access is granted **based on roles and permissions**.

### **3.2 Authorization Flow**

- **Public Endpoints (`/api/public`)** → Accessible to everyone.
- **Protected Endpoints (`/api/user`)** → Only accessible to users with the `ROLE_USER`.
- **Admin Endpoints (`/api/admin`)** → Only accessible to users with the `ROLE_ADMIN`.

🔹 **Spring Security checks the JWT claims** (e.g., roles, expiration, issuer) before allowing access.

---

## **Conclusion**

- ✅ **Use Spring OAuth2 Resource Server** to validate JWT tokens.
- ✅ **Protect endpoints with roles & permissions**.
- ✅ **Use Spring Authorization Server** to issue JWT tokens.
- ✅ **Use JWT tokens for stateless authentication.**

`The spring-boot-starter-oauth2-client dependency is not included because this guide focuses on securing a monolithic
 REST API that acts as an OAuth2 Resource Server and an Authorization Server.`

## When to Use spring-boot-starter-oauth2-client

You would add the oauth2-client dependency if your application needs to act as an OAuth2 client, meaning it would:

1. Request tokens from an Authorization Server (e.g., for calling third-party APIs).
2. Use OAuth2 login for user authentication (e.g., logging in via Google, GitHub, etc.).
3. Support Single Sign-On (SSO).

For a backend-only REST API, the OAuth2 Client is usually not needed unless your API itself needs to authenticate
against another service.

# Securing a Microservices-Based Spring Boot REST API using Spring OAuth2

This guide explains how to secure a **microservices-based Spring Boot REST API** using **Spring Security with OAuth2 and
Spring Authorization Server**.

## **1. Dependencies**

Each microservice will require specific dependencies.

### **1.1 Authorization Server (Auth Service)**

This service issues JWT tokens.

```xml

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

### **1.2 Resource Server (Protected API Services)**

Each microservice that requires authentication will act as a **Resource Server**.

```xml

<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

---

## **2. Configuration**

### **2.1 Authorization Server Configuration (Auth Service)**

Create `AuthorizationServerConfig.java`:

```java

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-id")
                .clientSecret("{noop}client-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }
}
```

### **2.2 Resource Server Configuration (Protected API Services)**

Each microservice that requires authentication should have the following configuration.

Create `SecurityConfig.java`:

```java

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public").permitAll()
                        .requestMatchers("/api/user").hasRole("USER")
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://auth-service:9000");
    }
}
```

### **2.3 Define Application Properties**

Each microservice should be configured to use the Authorization Server.

#### **Authorization Server (`auth-service`) Configuration:**

```yaml
server:
  port: 9000

spring:
  security:
    oauth2:
      authorization-server:
        issuer: http://auth-service:9000
```

#### **Resource Server (`api-service`) Configuration:**

```yaml
server:
  port: 8081

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://auth-service:9000
```

---

## **3. Flow: How Authentication and Authorization Work**

### **3.1 Authentication Flow**

1. **User logs in** by making a request to the Authorization Server (`auth-service`).
2. The Authorization Server **issues a JWT token** to the user.
3. The user includes the JWT token in the `Authorization` header when making requests to the microservices.
   ```http
   GET /api/user HTTP/1.1
   Host: api-service
   Authorization: Bearer eyJhbGciOiJIUzI1...
   ```
4. The API service **validates the JWT token** by checking with the Authorization Server (`http://auth-service:9000`).
5. If valid, access is granted based on roles and permissions.

### **3.2 Authorization Flow**

- **Public Endpoints (`/api/public`)** → Accessible to everyone.
- **Protected Endpoints (`/api/user`)** → Only accessible to users with `ROLE_USER`.
- **Admin Endpoints (`/api/admin`)** → Only accessible to users with `ROLE_ADMIN`.

🔹 **Spring Security verifies JWT claims** before granting access.

---

## **Conclusion**

- ✅ **Use Spring Authorization Server** to issue JWT tokens.
- ✅ **Protect each microservice as a Resource Server**.
- ✅ **Use JWT for stateless authentication**.
- ✅ **Microservices authenticate requests using tokens from the centralized Auth Server**.

`OAuth2 client dependency is not used here as well`

## Why It’s Not Used Here:

1. The Authorization Server issues JWT tokens, and Resource Servers only validate them. They do not need to act as
   OAuth2 clients.
2. The microservices authenticate API requests, but they do not log in users or request tokens from other OAuth2
   providers.

# Authorization Grant Types in OAuth2

OAuth2 defines several **Authorization Grant Types** that determine how a client application obtains an access token to
access protected resources. Each grant type serves different use cases, ranging from web applications to
machine-to-machine authentication.

## 1. Authorization Code Grant

### **Flow:**

1. The user logs into an authorization server.
2. The server redirects the user to a **callback URL** with an **authorization code**.
3. The client exchanges the code for an **access token**.

### **Use Case:**

- Used for web applications with a **front-end** and **back-end**.
- Provides enhanced security because the client secret is stored securely in the back-end.

### **Example:**

```http
GET /authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read_profile HTTP/1.1
```

## 2. Implicit Grant (Deprecated)

### **Flow:**

1. The user logs into the authorization server.
2. The server **immediately returns an access token** in the redirect URL.
3. No client authentication is required.

### **Use Case:**

- Previously used for **single-page applications (SPAs)**.
- Now deprecated due to security risks (access token is exposed in the URL).

## 3. Client Credentials Grant

### **Flow:**

1. The client (e.g., a backend service) authenticates directly with the authorization server using **client ID and
   secret**.
2. The server returns an **access token**.

### **Use Case:**

- Used for **machine-to-machine** (M2M) communication where no user is involved.

### **Example:**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=client_credentials
```

## 4. Resource Owner Password Credentials (ROPC) Grant

### **Flow:**

1. The user provides **username and password** directly to the client.
2. The client sends these credentials to the authorization server.
3. The server validates them and returns an **access token**.

### **Use Case:**

- Used when the client application is **highly trusted** (e.g., a mobile app from the same provider as the API).
- **Not recommended** due to security concerns.

### **Example:**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=USER&password=PASS&grant_type=password&client_id=CLIENT_ID
```

## 5. Refresh Token Grant

### **Flow:**

1. The client exchanges a **refresh token** (previously issued) for a **new access token**.
2. The server validates the refresh token and issues a new access token.

### **Use Case:**

- Allows users to stay logged in **without re-entering credentials**.
- Used in combination with other grants.

### **Example:**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

refresh_token=REFRESH_TOKEN&grant_type=refresh_token&client_id=CLIENT_ID
```

---

## **Comparison of OAuth2 Grant Types**

| Grant Type                     | Best For                        | Security Level | Requires User Login? |
|--------------------------------|---------------------------------|----------------|----------------------|
| Authorization Code             | Web apps (back-end + front-end) | High           | ✅ Yes                |
| Implicit (Deprecated)          | SPAs (front-end only)           | Low            | ✅ Yes                |
| Client Credentials             | Machine-to-machine (M2M)        | High           | ❌ No                 |
| Resource Owner Password (ROPC) | Legacy systems, trusted apps    | Low            | ✅ Yes                |
| Refresh Token                  | Extending session duration      | High           | ❌ No                 |

---

## **Conclusion**

- **Use Authorization Code** for web apps (**best practice**).
- **Use Client Credentials** for machine-to-machine communication.
- **Avoid Implicit Grant** (deprecated).
- **Avoid ROPC** unless absolutely necessary.
- **Use Refresh Tokens** to maintain sessions efficiently.
