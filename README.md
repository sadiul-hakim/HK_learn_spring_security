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

`You can provide lamda (http) -> {} and provide some custome configuration`.

