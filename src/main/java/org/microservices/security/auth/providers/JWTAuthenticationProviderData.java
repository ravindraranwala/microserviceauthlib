package org.microservices.security.auth.providers;

/**
 * Defines the data format needed by the {@link JWTAuthenticationProvider}
 * 
 * @author URANWRA
 *
 */
public interface JWTAuthenticationProviderData {
	/**
	 * Fetches the secret for the JWT auth endpoint.
	 * 
	 * @return secret for the JWT auth endpoint
	 */
	String getSecret();

	/**
	 * Fetches the token validity period in seconds.
	 * 
	 * @return token validity period in seconds.
	 */
	long getTokenValidityInSeconds();

	long getTokenValidityInSecondsForRememberMe();
}
