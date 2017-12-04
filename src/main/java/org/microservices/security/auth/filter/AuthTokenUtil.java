package org.microservices.security.auth.filter;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.StringUtils;

/**
 * Defines all the utility functions used during the authentication and
 * authorization process.
 * 
 * @author URANWRA
 *
 */
public class AuthTokenUtil {
	/**
	 * Extracts the Authentication token from the incoming HTTP request.
	 * 
	 * @param request
	 *            incoming HTTP request.
	 * @return token extracted from the HTTP header if exists, null otherwise.
	 */
	public static String resolveToken(HttpServletRequest request) {
		final String bearerToken = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
		if (bearerToken != null) {
			if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AuthConstants.BEARER)) {
				/*
				 * If it is a Bearer token skip off the first 7 chars and extract the token
				 * itself from the HTTP Header. This is normally used with JWT style tokens.
				 */
				return bearerToken.substring(7, bearerToken.length());
			}
		} else {
			/*
			 * Otherwise handle the X-Authorization HTTP Header which is used in Pi
			 * authentication.
			 */
			return request.getHeader(AuthConstants.X_AUTHORIZATION_HEADER);
		}
		return null;
	}
}