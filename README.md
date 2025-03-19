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

---

### 5️⃣ Conclusion

- **CSRF is enabled by default** in Spring Security.
- **Disable CSRF for stateless REST APIs** (e.g., JWT-based authentication).
- **Use `CookieCsrfTokenRepository` for AJAX-based apps**.
- **Customize CSRF handling using `CsrfTokenRepository`** for advanced use cases.

Let me know if you need help integrating this into your **SpringBase** project! 🚀

## Social Login (OAuth2) - Google

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

## Basic Auth

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

## Form Login

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

Would you like a hands-on guide on implementing one of these? 🚀