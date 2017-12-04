package org.microservices.security.auth.data;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Provides an easy way for the client to retrieve the currently authenticated
 * principal.
 * 
 * @author URANWRA
 *
 */
public class AuthenticationFacade {

	/**
	 * Retrieves the currently authenticated principal.
	 * 
	 * @return Principal associated with the currently authenticated user.
	 */
	public static Authentication getAuthentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	/**
	 * Retrieves the token of the currently authenticated user.
	 * 
	 * @return authentication token.
	 */
	public static String getToken() {
		return SecurityContextHolder.getContext().getAuthentication().getCredentials().toString();
	}

	/**
	 * Retrieves the user name of the currently authenticated user.
	 * 
	 * @return user name of the principal.
	 */
	public static String getName() {
		return SecurityContextHolder.getContext().getAuthentication().getName();
	}

	/**
	 * Retrieves the correlation id used for auditing purposes during the system to
	 * system communication.
	 * 
	 * @return correlation id value.
	 */
	public static String getCorrelationId() {
		throw new UnsupportedOperationException();
	}

}
