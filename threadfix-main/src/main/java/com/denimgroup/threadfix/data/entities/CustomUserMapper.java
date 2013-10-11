package com.denimgroup.threadfix.data.entities;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import com.denimgroup.threadfix.plugin.permissions.PermissionServiceDelegateFactory;
import com.denimgroup.threadfix.service.CustomUserDetailService;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;


public class CustomUserMapper implements UserDetailsContextMapper {

	protected final SanitizedLogger log = new SanitizedLogger(CustomUserMapper.class);

	private DefaultConfigService defaultConfigService = null;
	private RoleService roleService = null;
	private UserService userService = null;
	private CustomUserDetailService customUserDetailService = null;

	@Autowired
	public CustomUserMapper(DefaultConfigService defaultConfigService,
			RoleService roleService, UserService userService,
			CustomUserDetailService customUserDetailService) {
		this.defaultConfigService = defaultConfigService;
		this.roleService = roleService;
		this.userService = userService;
		this.customUserDetailService = customUserDetailService;
	}

	/**
	 * Strategy is :
	 * 1. Look up the user.
	 * 2. If present, load their permissions.
	 * 3. If not present, give default permissions.
	 */
	@Override
	public UserDetails mapUserFromContext(DirContextOperations arg0,
			String userName, Collection<? extends GrantedAuthority> arg2) {

		log.info("User " + userName + " logged in successfully at " + new Date());
		User dbUser = userService.loadLdapUser(userName);

		if (dbUser != null) {
			return customUserDetailService.loadUser(dbUser);
		}

		Set<GrantedAuthority> newAuthorities = new HashSet<GrantedAuthority>();

		newAuthorities.add(new BasicGrantedAuthority(Role.USER));

		if (PermissionServiceDelegateFactory.isEnterprise()) {

			DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

			if (config.getGlobalGroupEnabled()) {
				newAuthorities.add(new BasicGrantedAuthority(Permission.READ_ACCESS.getText()));

				if (config.getDefaultRoleId() != null) {
					Role testRole = roleService.loadRole(config.getDefaultRoleId());
					if (testRole != null) {
						for (Permission permission : testRole.getPermissions()) {
							newAuthorities.add(new BasicGrantedAuthority(permission.getText()));
						}
					}
				}
			}
		} else {
			for (Permission permission : Permission.values()) {
				if (permission != Permission.CAN_MANAGE_ROLES) {
					newAuthorities.add(new BasicGrantedAuthority(permission.getText()));
				}
			}
		}

		return new ThreadFixUserDetails(userName, "ldap", true, true, true, true,
				newAuthorities, "", true, true, 1, null, null);
	}
	
	private class BasicGrantedAuthority implements GrantedAuthority {
		private static final long serialVersionUID = 4703684877652818549L;

		final String authority;

		public BasicGrantedAuthority(String authority) {
			this.authority = authority;
		}
		
		@Override
		public String getAuthority() {
			return authority;
		}
	}

	@Override
	public void mapUserToContext(UserDetails arg0, DirContextAdapter arg1) { }

}
