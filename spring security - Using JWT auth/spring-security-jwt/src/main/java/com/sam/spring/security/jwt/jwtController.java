package com.sam.spring.security.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class jwtController {

	private JwtEncoder jwtEncoder;

	public jwtController(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	

	@GetMapping("/test")
	public String test() {
		return "Test is working";
	}

	@GetMapping("/auth")
	public Authentication authenticate(Authentication auth) {
		return auth;
	}

	@GetMapping("/jwt")
	public jwtResponse authenticate1(Authentication auth) {
		return new jwtResponse(createToekn(auth));
	}

	private String createToekn(Authentication auth) {

/*		var claims = JwtClaimsSet.builder()
				.issuer(auth.getName())
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(60 * 1))
				.claim("scope", createScope(auth)).build();
		
*/		
		JwtClaimsSet claims = JwtClaimsSet.builder()
		        .issuer("self")
		        .subject(auth.getName())
		        .issuedAt(Instant.now())
		        .expiresAt(Instant.now().plusSeconds(900))
		        .claim("scope", createScope(auth))
		        .build();


		JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);

		return jwtEncoder.encode(parameters).getTokenValue();
	}

	private String createScope(Authentication auth) {

		return auth.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.joining(" "));
	}

}

record jwtResponse(String name) {

}
