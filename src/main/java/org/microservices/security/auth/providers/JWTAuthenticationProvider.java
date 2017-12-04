/**
 * PEARSON PROPRIETARY AND CONFIDENTIAL INFORMATION SUBJECT TO NDA
 * Copyright © 2017 Pearson Education, Inc.
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Pearson Education, Inc.  The intellectual and technical concepts contained
 * herein are proprietary to Pearson Education, Inc. and may be covered by U.S. and Foreign Patents,
 * patent applications, and are protected by trade secret or copyright law.
 * Dissemination of this information, reproduction of this material, and copying or distribution of this software
 * is strictly forbidden unless prior written permission is obtained
 * from Pearson Education, Inc.
 */
package org.microservices.security.auth.providers;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

/**
 * {@link TokenProvider} implementation for JWT authentication.
 * 
 * @author URANWRA
 *
 */
public class JWTAuthenticationProvider extends DefaultAuthenticationProvider {

	private static final int MILLIS_IN_SECOND = 1000;

	private final Logger log = LoggerFactory.getLogger(JWTAuthenticationProvider.class);

	private static final String AUTHORITIES_KEY = "auth";

	private final String secret;
	private final long tokenValidityInSeconds;
	private final long tokenValidityInSecondsForRememberMe;

	/**
	 * Constructs an instance of {@link JWTAuthenticationProvider} with the given
	 * values in it.
	 * 
	 * @param jwtTokenProviderData
	 *            data needed by the {@link JWTAuthenticationProvider} to work.
	 */
	public JWTAuthenticationProvider(JWTAuthenticationProviderData jwtTokenProviderData) {
		super();
		this.secret = jwtTokenProviderData.getSecret();
		this.tokenValidityInSeconds = jwtTokenProviderData.getTokenValidityInSeconds();
		this.tokenValidityInSecondsForRememberMe = jwtTokenProviderData.getTokenValidityInSecondsForRememberMe();
	}

	public String createToken(Authentication authentication, Boolean rememberMe) {
		String authorities = authentication.getAuthorities().stream().map(authority -> authority.getAuthority())
				.collect(Collectors.joining(","));

		long now = (new Date()).getTime();
		Date validity;
		if (rememberMe) {
			validity = new Date(now + MILLIS_IN_SECOND * this.tokenValidityInSecondsForRememberMe);
		} else {
			validity = new Date(now + MILLIS_IN_SECOND * this.tokenValidityInSeconds);
		}

		return Jwts.builder().setSubject(authentication.getName()).claim(AUTHORITIES_KEY, authorities)
				.signWith(SignatureAlgorithm.HS512, this.secret).setExpiration(validity).compact();
	}

	@Override
	protected boolean isValid(String authToken) {
		try {
			Jwts.parser().setSigningKey(this.secret).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			log.info("Invalid JWT signature: " + e.getMessage());
			return false;
		} catch (IllegalArgumentException e) {
			log.info("Invalid JWT token: " + e.getMessage());
			return false;
		}
	}

	@Override
	protected Authentication getAuthentication(String token) {
		Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();

		Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(claims.get(AUTHORITIES_KEY).toString().split(",")).stream()
				.map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());

		User principal = new User(claims.getSubject(), "", authorities);

		return new PreAuthenticatedAuthenticationToken(principal, token, authorities);
	}
}
