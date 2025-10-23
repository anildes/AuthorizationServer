
The Java program AuthorizationServerConfig configures a Spring Authorization Server using Spring Security. It sets up the necessary components for handling OAuth2 token issuance, client authentication, and JWT signing/validation. Here's a breakdown of its key components:
Authorization Server Security Filter Chain:
Configures the /oauth2/token endpoint for token issuance.
Enables OpenID Connect (OIDC) discovery.
Secures endpoints with authentication and configures CSRF protection for OAuth2 endpoints.
Default Security Filter Chain:
Provides a fallback security configuration for other endpoints (e.g., /login).
Registered Client Repository:
Defines an in-memory client (zuul-gateway-client) with:
Client ID and secret.
CLIENT_SECRET_BASIC authentication method.
CLIENT_CREDENTIALS grant type.
Scopes for access control.
JWT Signing Key:
Generates an RSA key pair for signing JWTs.
Exposes the public key via a JWKS endpoint.
JWT Decoder:
Configures a JwtDecoder to validate tokens using the server's own JWKS endpoint (/oauth2/jwks).
Authorization Server Settings:
Specifies the issuer URI (http://localhost:8081) for tokens.
This program is part of an OAuth2 Authorization Server implementation, enabling secure token issuance and validation for client applications.

download and compile the program using pom and point to jdk1.8 in your IDE 
Put  clientId("zuul-gateway-client")    
 put clientSecret("gateway-secret-123")
 in the application.properties of your application or resource server 
