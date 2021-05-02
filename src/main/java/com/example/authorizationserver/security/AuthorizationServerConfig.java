package com.example.authorizationserver.security;

import com.example.authorizationserver.service.CustomUserDetailsService;
import com.example.authorizationserver.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Value("${auth.client-id}")
	private String clientId;

	@Value("${auth.client-secret}")
	private String clientSecret;

	@Value("${auth.access-token-validity-seconds:}")
	private int accessTokenValiditySeconds;

	@Value("${auth.refresh-token-validity-seconds:}")
	private int refreshTokenValiditySeconds;

	private static final String GRANT_TYPE_PASS = "password";

	private static final String AUTHORIZATION_CODE = "authorization_code";

	private static final String REFRESH_TOKEN = "refresh_token";

	private static final String IMPLICIT = "implicit";

	private static final String SCOPE_READ = "read";

	private static final String SCOPE_WRITE = "write";


	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomAccessTokenConverter customAccessTokenConverter;

	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setSigningKey(SecurityUtils.SIGNING_KEY);
		converter.setAccessTokenConverter(customAccessTokenConverter);
		return converter;
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(accessTokenConverter());
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
		configurer.inMemory().withClient(clientId).secret(passwordEncoder().encode(clientSecret))
				.authorizedGrantTypes(GRANT_TYPE_PASS, AUTHORIZATION_CODE, REFRESH_TOKEN,
						IMPLICIT)
				.scopes(SCOPE_READ, SCOPE_WRITE)
				.accessTokenValiditySeconds(accessTokenValiditySeconds)
				.refreshTokenValiditySeconds(refreshTokenValiditySeconds);
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.allowFormAuthenticationForClients();
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(
				Arrays.asList(tokenEnhancer(), accessTokenConverter()));
		endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager)
				.tokenEnhancer(tokenEnhancerChain).reuseRefreshTokens(false)
				.accessTokenConverter(accessTokenConverter())
				.userDetailsService(customUserDetailsService);
	}


	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new CustomTokenEnhancer();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
