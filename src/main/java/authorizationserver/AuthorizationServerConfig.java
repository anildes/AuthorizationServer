package authorizationserver;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder; // NEW IMPORT
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder; // NEW IMPORT
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Configuration class for the Spring Authorization Server (SAS) - v0.4.0 compatible.
 * This sets up the token endpoint and defines our client credentials client.
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    /**
     * Defines the primary security filter chain for the Authorization Server endpoints.
     * The token endpoint (/oauth2/token) is exposed here.
     * @param http HttpSecurity configuration builder.
     * @return The configured SecurityFilterChain.
     * @throws Exception if configuration fails.
     */
    @Bean
    @Order(1) // Ensures this runs before the default Spring Security filter chain (Order 2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        // CRITICAL: Configure the authorization server to handle token requests
        http.apply(authorizationServerConfigurer);

        // Required for the OpenID Connect discovery endpoint
        authorizationServerConfigurer.oidc(Customizer.withDefaults());

        // Set up the form login for any unauthorized requests to the token endpoint
        http.exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(
                        // Redirects unauthorized users to a login page (default Spring login)
                        new LoginUrlAuthenticationEntryPoint("/login")
                )
        )
        // Enable basic HTTP security for other endpoints not handled by the SAS config.
        // The JwtDecoder bean defined below satisfies the requirement for this part.
        .oauth2ResourceServer(oauth2ResourceServer ->
                oauth2ResourceServer.jwt(Customizer.withDefaults())
        )
        // Must explicitly use new AntPathRequestMatcher for 5.x compatibility
        .csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/oauth2/**")))
        .authorizeRequests(auth -> auth.anyRequest().authenticated()); // Secure all other requests

        return http.build();
    }

    /**
     * Defines a simple default security filter chain for all other endpoints (e.g., /login).
     * @param http HttpSecurity configuration builder.
     * @return The configured SecurityFilterChain.
     * @throws Exception if configuration fails.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests(authorizeRequests ->
                    authorizeRequests.anyRequest().authenticated()
            )
            // Default Spring Security form login for basic authentication
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Configures the client(s) that can request tokens.
     * THIS IS YOUR ZUUL GATEWAY CLIENT.
     * * @return An InMemory repository containing the client definition.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient zuulGatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
            // ** IMPORTANT: This is the Client ID your Zuul Gateway must use **
            .clientId("zuul-gateway-client")

            // ** IMPORTANT: This is the Client Secret. {noop} means plain text for development. **
            .clientSecret("{noop}gateway-secret-123")

            // Defines the authentication method (Basic Auth or POST body)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)

            // CRITICAL: Enable the Client Credentials Grant type
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)

            // Define the scopes (permissions) the client is allowed to request
            .scope("internal.service.access")
            .scope("api.read")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build();

        return new InMemoryRegisteredClientRepository(zuulGatewayClient);
    }

    /**
     * Provides the signing key needed to create the JWT (Access Token).
     * @return JWKSource implementation (In-memory RSA key pair).
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    // Helper method to generate an RSA key pair for JWT signing
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * CRITICAL FIX: Defines the JwtDecoder required by the internal Resource Server component.
     * It fetches the public keys from the server's own JWKS endpoint (exposed by the SAS config).
     * @return A JwtDecoder bean.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        // Since the server runs on 8081, we point the decoder to its own public key endpoint.
        // This is necessary to validate tokens issued by this server when using the 
        // .oauth2ResourceServer().jwt() configuration above.
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8081/oauth2/jwks").build();
    }
    
    /**
     * Configures the Authorization Server's issuer URI (where tokens come from).
     * @return AuthorizationServerSettings bean.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // FIXED: Issuer URL updated to use the correct port 8081
        return AuthorizationServerSettings.builder().issuer("http://localhost:8081").build();
    }
}
