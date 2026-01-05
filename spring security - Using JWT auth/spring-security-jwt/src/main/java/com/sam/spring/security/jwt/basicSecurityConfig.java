package com.sam.spring.security.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class basicSecurityConfig {
	/*
	 * // @Bean public SecurityFilterChain securityFilterChain1(HttpSecurity http)
	 * throws Exception {
	 * 
	 * // http.authenticationProvider(authprovider());
	 * 
	 * http.authorizeHttpRequests(req ->
	 * req.requestMatchers("createuser").permitAll());
	 * 
	 * http.authorizeHttpRequests(auth -> { auth.anyRequest().authenticated(); });
	 * 
	 * http.sessionManagement(session ->
	 * session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
	 * 
	 * // http.formLogin(); http.httpBasic(Customizer.withDefaults());
	 * 
	 * http.csrf(csrf -> csrf.disable());
	 * 
	 * // http.csrf(AbstractHttpConfigurer::disable);
	 * 
	 * // http.addFilterBefore(null, UsernamePasswordAuthenticationFilter.class);
	 * return http.build(); }
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(auth -> {
			auth.anyRequest().authenticated();
		});

		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		http.httpBasic(Customizer.withDefaults());

		http.csrf(csrf -> csrf.disable());

		http.headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable()));

		http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();

	}

	@Bean
	public UserDetailsService userDetails1() {

		var User1 = User.withUsername("sk").password("{noop}dummy").roles("USER").build();
		var admin = User.withUsername("admin").password("{noop}123").roles("ADMIN", "User").build();

		return new InMemoryUserDetailsManager(User1, admin);

	}

	@Bean
	public KeyPair keypair() {

		try {
			KeyPairGenerator KeyPairGenerator = java.security.KeyPairGenerator.getInstance("RSA");
			KeyPairGenerator.initialize(2048);
			return KeyPairGenerator.generateKeyPair();

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Bean
	public RSAKey rasKey(KeyPair keypair) {

		return new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).privateKey(keypair.getPrivate())
				.keyID(UUID.randomUUID().toString()).build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rasKey) {

		var jwkSet = new JWKSet(rasKey);

		/*
		 * this full method of anyonoums inner type implement var jwkSource = new
		 * JWKSource() {
		 * 
		 * @Override public List<JWK> get(JWKSelector jwkSelector, SecurityContext
		 * context) throws KeySourceException { return jwkSelector.select(jwkSet); } };
		 * 
		 */

		return (JWKSelector, context) -> JWKSelector.select(jwkSet);

	}

	@Bean
	public JwtDecoder jwtDecoder(RSAKey rasKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rasKey.toRSAPublicKey()).build();

	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);

	}

}
