package org.microservices.security.auth.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

/**
 * Filters incoming requests and installs a Spring Security principal if a
 * header corresponding to a valid user is found. This is an implementation of
 * the {@link AbstractAuthenticationProcessingFilter}
 * 
 * @author URANWRA
 *
 */
public class TokenAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private final Logger log = LoggerFactory.getLogger(TokenAuthenticationProcessingFilter.class);

	private final AuthenticationProvider authenticationProvider;

	private final AuthenticationSuccessHandler authenticationSuccessHandler;

	private final AuthenticationFailureHandler authenticationFailureHandler;

	/**
	 * Constructs a {@link Filter} with the given {@link AuthenticationProvider} in
	 * it.
	 * 
	 * @param authProvider
	 *            {@link AuthenticationProvider} used for the authentication
	 *            process.
	 * @param filterProcessesUrl
	 *            the URL that determines if authentication is required
	 * @param authenticationSuccessHandler
	 *            optional {@link AuthenticationSuccessHandler} to do redirection or
	 *            so upon successful authentication.
	 * @param authenticationFailureHandler
	 *            required {@link AuthenticationFailureHandler} to handle
	 *            authentication failure scenarios.
	 */
	public TokenAuthenticationProcessingFilter(AuthenticationProvider authProvider, String filterProcessesUrl,
			AuthenticationSuccessHandler authenticationSuccessHandler,
			AuthenticationFailureHandler authenticationFailureHandler) {
		super(filterProcessesUrl);
		Assert.notNull(authenticationFailureHandler, "Authentication Failure Handler can not be null");
		this.authenticationProvider = authProvider;
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		String token = AuthTokenUtil.resolveToken(request);
		return this.authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(null, token));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(authentication);

		/*
		 * Notice that the authentication success handler is optional. If it is
		 * provided, then we invoke it.
		 */
		if (this.authenticationSuccessHandler != null) {
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
		}
		// invoking the next chain in the filter.
		chain.doFilter(request, response);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		log.error("Security exception for user {} - {}", e.getMessage());
		authenticationFailureHandler.onAuthenticationFailure(request, response, e);
	}

}
