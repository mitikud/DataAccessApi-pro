package com.example.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    // 1. Protect the OAuth2 Authorization Server endpoints.
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http) throws Exception {

//        OAuth2AuthorizationServerConfiguration
//                .applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // Apply security only to Authorization Server endpoints.
                .securityMatcher(
                        authorizationServerConfigurer.getEndpointsMatcher()
                )

                // Configure OAuth2 Authorization Server.
                .with(
                        authorizationServerConfigurer,
                        Customizer.withDefaults()
                )

                // All OAuth2 Authorization Server endpoints require
                // authentication unless the protocol permits otherwise.
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )

                // Redirect unauthenticated browser requests to login.
                .exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );


        return http.build();
    }


    // 2. Configure security for remaining endpoints.
    @Bean
    @Order(2)
    SecurityFilterChain applicationSecurityFilterChain(
            HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
        );

        http.formLogin(Customizer.withDefaults());

        return http.build();
    }

    // 3. Hash OAuth client secrets.
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 4. Register microservice clients.
    @Bean
    RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder) {

        RegisteredClient customerClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("customer-service")
                .clientSecret(passwordEncoder.encode("customer-secret"))
                .clientAuthenticationMethod(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                )
                .authorizationGrantType(
                        AuthorizationGrantType.CLIENT_CREDENTIALS
                )
                .scope("daa.customers.read")
                .scope("daa.customers.write")
                .tokenSettings(TokenSettings.builder()
                                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                                            .build())
                .build();

        RegisteredClient orderClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("order-service")
                .clientSecret(passwordEncoder.encode("order-secret"))
                .clientAuthenticationMethod(
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                )
                .authorizationGrantType(
                        AuthorizationGrantType.CLIENT_CREDENTIALS
                )
                .scope("daa.orders.read")
                .scope("daa.orders.write")
                .tokenSettings(TokenSettings.builder()
                                            .accessTokenTimeToLive(Duration.ofMinutes(15))
                                            .build())
                .build();

        return new InMemoryRegisteredClientRepository(
                customerClient,
                orderClient
        );
    }

    // 5. Create RSA signing keys for local development.
    @Bean
    com.nimbusds.jose.jwk.source.JWKSource<SecurityContext> jwkSource()
            throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder(
                (RSAPublicKey) keyPair.getPublic()
        )
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // 6. Enable JWT decoding.
    @Bean
    JwtDecoder jwtDecoder(
            com.nimbusds.jose.jwk.source.JWKSource<SecurityContext>
                    jwkSource) {

        return OAuth2AuthorizationServerConfiguration
                .jwtDecoder(jwkSource);
    }

    // 7. Configure the token issuer.
    @Bean
    AuthorizationServerSettings authorizationServerSettings() {

        return AuthorizationServerSettings.builder()
                                          .issuer("http://localhost:8084")
                                          .build();
    }


    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {

        return context -> {

            if ("access_token".equals(
                    context.getTokenType().getValue())) {

                context.getClaims()
                       .audience(List.of("daa-api"));
            }
        };
    }
}