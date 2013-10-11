package com.denimgroup.threadfix.service;

import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.AuthenticatedLdapEntryContextCallback;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapEntryIdentification;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.data.entities.CustomUserMapper;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;

public class LdapAuthenticator extends SpringBeanAutowiringSupport implements AuthenticationProvider {
	
	@Autowired
	DefaultConfigService defaultConfigService;
	
	@Autowired
	CustomUserMapper customUserMapper;

	private LdapTemplate ldapTemplate = null;

	private LdapAuthenticator() {}
	
	private static class ContextConfigHolder extends SpringBeanAutowiringSupport {
		
		final String base, url, username, credentials;
		
		public ContextConfigHolder(DefaultConfigService defaultConfigService) {
			DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();
			
			this.base = config.getActiveDirectoryBase();
			this.url = config.getActiveDirectoryURL();
			this.username = config.getActiveDirectoryUsername();
			this.credentials = config.getActiveDirectoryCredentials();
		}
	}

	private class MyContextSource extends LdapContextSource {
		public MyContextSource() {
			ContextConfigHolder holder = new ContextConfigHolder(defaultConfigService);
			
			setBase(holder.base);
			setUrl(holder.url);
			setAuthenticationStrategy(new SimpleDirContextAuthenticationStrategy());
			setAuthenticationSource(new SimpleCredentialsHolder(holder.username, holder.credentials));
		}
		
		@Override
		protected Hashtable<String, String> getAnonymousEnv() {
			return setupAnonymousEnv();
		}
		
		private Hashtable<String, String> setupAnonymousEnv() {
			Hashtable<String, String> env = new Hashtable<>();

			env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			env.put(Context.PROVIDER_URL, assembleProviderUrlString(getUrls()));

			return env;
		}
	}
	
	// the rest of this file is taken from the LdapTemplate file and converted to work in this setting.
	
	public boolean innerAuthenticate(String username, String password) {

		MyContextSource contextSource = this.new MyContextSource();
		ldapTemplate = new LdapTemplate(contextSource);

		Name base = DistinguishedName.EMPTY_PATH;
		final AuthenticatedLdapEntryContextCallback callback = new NullAuthenticatedLdapEntryContextCallback();
		//final AuthenticationErrorCallback errorCallback = new NullAuthenticationErrorCallback();

		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter("objectclass", "person")).and(new EqualsFilter("cn", username));
		String filterString = filter.toString();

		List<?> result = ldapTemplate.search(base, filterString, new MyContextMapper());
		if (result.size() == 0) {
//			String msg = "No results found for search, base: '" + base + "'; filter: '" + filterString + "'.";
//			log.info(msg);
			return false;
		} else if (result.size() > 1) {
			String msg = "base: '" + base + "'; filter: '" + filterString + "'.";
			throw new IncorrectResultSizeDataAccessException(msg, 1, result.size());
		}

		final LdapEntryIdentification entryIdentification = (LdapEntryIdentification) result.get(0);

		try {
			DirContext ctx = new MyContextSource().getContext(entryIdentification.getAbsoluteDn().toString(), password);

			try {
				new ContextExecutor() {
					@Override
					public Object executeWithContext(DirContext ctx) throws javax.naming.NamingException {
						callback.executeWithContext(ctx, entryIdentification);
						return null;
					}
				}.executeWithContext(ctx);
			}
			catch (javax.naming.NamingException e) {
				throw LdapUtils.convertLdapException(e);
			}
			finally {
				closeContext(ctx);
			}
			return true;
		}
		catch (Exception e) {
//			log.info("Authentication failed for entry with DN '" + entryIdentification.getAbsoluteDn() + "'", e);
			//errorCallback.execute(e);
			return false;
		}
	}
	
	private void closeContext(DirContext dirContext) {
		if (dirContext != null) {
			try {
				dirContext.close();
			}
			catch (Exception e) {
				// Never mind this.
			}
		}
	}

	private static final class NullAuthenticatedLdapEntryContextCallback
			implements AuthenticatedLdapEntryContextCallback {
		@Override
		public void executeWithContext(DirContext ctx,
				LdapEntryIdentification ldapEntryIdentification) {
			// Do nothing
		}
	}
	
	private static final class SimpleCredentialsHolder implements AuthenticationSource {
		
		private final String principal, credentials;
		
		public SimpleCredentialsHolder(String principal, String credentials) {
			this.principal = principal;
			this.credentials = credentials;
		}
		
		@Override
		public String getPrincipal() {
			return principal;
		}
		
		@Override
		public String getCredentials() {
			return credentials;
		}
	}
	
	private static final class MyContextMapper implements ContextMapper {
		@Override
		public Object mapFromContext(Object ctx) {
			
			LdapContext adapter = (LdapContext) ctx;
			
			try {
				return new LdapEntryIdentification(new DistinguishedName(
						adapter.getNameInNamespace()), new DistinguishedName(
						adapter.getNameInNamespace()));
			} catch (NamingException e) {
				e.printStackTrace();
			}
			
			return null;
		}
	}

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		
		if (authentication != null && authentication.getName() != null &&
				authentication.getCredentials() != null &&
				innerAuthenticate(authentication.getName(), authentication.getCredentials().toString())) {
			
			UserDetails user = customUserMapper.mapUserFromContext(null, authentication.getName(), null);

			return createSuccessfulAuthentication(authentication, user);
		} else {
			throw new ThreadFixActiveDirectoryAuthenticationException("Authentication failed.");
		}
	}
	
	protected Authentication createSuccessfulAuthentication(Authentication authentication,
            UserDetails user) {
        Object password = authentication.getCredentials();

        UsernamePasswordAuthenticationToken result =
        		new UsernamePasswordAuthenticationToken(user, password, user.getAuthorities());
        result.setDetails(authentication.getDetails());

        return result;
    }
	
	private static final class ThreadFixActiveDirectoryAuthenticationException extends AuthenticationException {

		public ThreadFixActiveDirectoryAuthenticationException(String msg) {
			super(msg);
		}

		private static final long serialVersionUID = 2346164382L;
	}
	
	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}
}
