////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//     All rights reserved worldwide.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Created by mcollins on 4/23/15.
 */
public interface SessionService {

    void reloadSession(Role role);

    void invalidateSessions(User user);

    void reloadSession(User user);

    UserDetails mapUserFromContext(DirContextOperations arg0,
                                   String userName, Collection<? extends GrantedAuthority> arg2);

    Authentication createSuccessfulAuthentication(Authentication authentication,
                                                  UserDetails user);
}
