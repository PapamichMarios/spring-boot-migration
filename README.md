Changes need to bump from 2.5.5 to 3.1.4

# Clean all your gradles from unnecessary dependencies!
Don't skip this 

# Gradle

#### Bump Gradle
Bump gradle to 7.6.1 in `gradle/wrapper/gradle-wrapper.properties`

#### Bump plugins

1. `id 'org.springframework.boot' version '2.5.5'` -> `id 'org.springframework.boot' version '3.1.4'`
2. `id 'io.spring.dependency-management' version '1.0.11.RELEASE'` -> `id 'io.spring.dependency-management' version '1.1.3'`

#### Spring cloud version

Add 
```
ext {
  springCloudVersion = "2022.0.3"
}
```

#### Update java to 17
`sourceCompatibility = '17'`

#### Update Dependencies
1. querydsl 4.4.0 -> 5.0.0
2. lombok 1.18.20 -> 1.18.30
3. mapstruct 1.4.2.Final -> 1.5.5.Final

#### Replace dependencies

1. `api group: 'io.swagger', name: 'swagger-annotations', version: '1.5.20'` -> `implementation group: 'io.swagger.core.v3', name: 'swagger-annotations', version: '2.2.15'`
2. `implementation 'org.apache.httpcomponents:httpclient:4.5.13'` -> `implementation group: 'org.apache.httpcomponents.client5', name: 'httpclient5', version: "${httpClientVersion}"` (httpClientVersion = '5.2.1')
3. `implementation group: 'io.jsonwebtoken', name: 'jjwt', version: '0.9.1'` -> `api group: 'io.jsonwebtoken', name: 'jjwt-api', version: "${jwtVersion}"` (jwtVersion = '0.12.0')

#### Querydsl

Remove everything querydsl related and just add (jakarta libraries):

```
api group: "com.querydsl", name: "querydsl-jpa", version: "${queryDslVersion}", classifier: "jakarta"
annotationProcessor group: "org.projectlombok", name: "lombok", version: "${lombokVersion}"
annotationProcessor group: "com.querydsl", name: "querydsl-apt", version: "${queryDslVersion}", classifier: "jakarta"
annotationProcessor group: "jakarta.persistence", name: "jakarta.persistence-api", version: "3.1.0"
```

# Replace `javax` with `jakarta`

Everything javax related is obsolete. Repalce with jakarta.

# Remove Zuul Proxy

Delete everything zuul proxy related from gradle, code, filters etc

# Repository

`PagingAndSortingRepository` does not extend `CrudRepository` anymore, so it is essential to extend repositories with either `CrudRepository` or `ListCrudRepository`

# Swagger

Remove

```
implementation group: 'io.springfox', name: 'springfox-boot-starter', version: '3.0.0'
implementation group: 'io.springfox', name: 'springfox-swagger-ui', version: '3.0.0'
```

Add

```
implementation group: 'org.springdoc', name: 'springdoc-openapi-ui', version: '1.7.0'
```


```
@Configuration
public class SwaggerConfig {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    @Value("${openapi.url}")
    private String url;

    @Bean
    public OpenAPI api() {

        Server server = new Server();
        server.setUrl(url);
        server.setDescription("Server URL");

        return new OpenAPI()
            .info(metaInfo()).servers(List.of(server))
            .components(new Components()
                .addSecuritySchemes("api_key", new SecurityScheme()
                    .type(SecurityScheme.Type.APIKEY)
                    .description("Api Key access")
                    .in(SecurityScheme.In.HEADER)
                    .name(AUTHORIZATION_HEADER)
                ))
            .security(Collections.singletonList(new SecurityRequirement().addList("api_key")));
    }

    /**
     * Return the meta info about the API. This should reflect
     */
    private Info metaInfo() {
        return new Info()
            .description("Backend API Project")
            .title("API")
            .version("2.0.0");
    }

}
```

Change annotations as per library:
https://springdoc.org/migrating-from-springfox.html


# Spring Security

Replace the `WebSecurityConfig.java` with:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  private static final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

  @Autowired
  private JwtAuthenticationEntryPoint jwtEntryPoint;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    return new JwtAuthenticationFilter();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    return http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(AbstractHttpConfigurer::disable)
        .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtEntryPoint))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests((authz) -> authz
            .requestMatchers("/api/auth/*").permitAll()
            .requestMatchers("/api/settings/*").permitAll()
            .requestMatchers("/resources/*").permitAll()
            .anyRequest().authenticated()
        )
        .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
        .build();
  }

  // TODO: fix wildcard
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(ImmutableList.of("*"));
    configuration.setAllowedMethods(ImmutableList.of("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(
        ImmutableList.of("Authorization", "Cache-Control", "Content-Type", "Content-disposition", "Access-Control-Expose-Headers"
            , "Organization"));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
```
