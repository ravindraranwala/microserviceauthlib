package org.microservices.security.auth.providers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Gives a sensible default implementation of the {@link AuthenticationProvider} contract
 * with hooks for validating the token and retrieving the token which has to be
 * implemented by the client using it's own authentication manager.
 * 
 * @author URANWRA
 *
 */
public abstract class DefaultAuthenticationProvider implements AuthenticationProvider {
	private final Logger log = LoggerFactory.getLogger(DefaultAuthenticationProvider.class);

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// If token is not valid, then merely throw an exception.
		final String token = (String) authentication.getCredentials();
		if (!this.isValid(token)) {
			log.info("Auth token is not valid. Marking request as invalid");
			throw new BadCredentialsException("Auth token is not valid.");
		}

		// If the token is valid, then return the Authentication object.
		return getAuthentication(token);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return PreAuthenticatedAuthenticationToken.class.equals(authentication);
	}

	/**
	 * Checks whether a given auth token is valid.
	 * 
	 * @param authToken
	 *            auth token to be validated.
	 * @return <code>true</code> if the token is valid, <code>false</code>
	 *         otherwise.
	 */
	protected abstract boolean isValid(String authToken);

	/**
	 * Fetches the {@link Authentication} associated with this token.
	 * 
	 * @param token
	 *            authentication token.
	 * @return {@link Authentication} associated with the given token.
	 */
	protected abstract Authentication getAuthentication(String token);

}
