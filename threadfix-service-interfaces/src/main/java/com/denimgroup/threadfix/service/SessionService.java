////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Created by mcollins on 4/23/15.
 */
public interface SessionService {

    void reloadSession(Role role);

    void reloadSession(User user);

    void reloadSession(Iterable<User> users);

    void invalidateSessions(User user);


    UserDetails mapUserFromContext(DirContextOperations arg0,
                                   String userName, Collection<? extends GrantedAuthority> arg2, LdapTemplate ldapTemplate);


    UserDetails mapUserFromContext(DirContextOperations arg0,
                                   String userName, Collection<? extends GrantedAuthority> arg2);

    @SuppressWarnings("unchecked")
    List<String> getPersonGroupsByAccountName(String accountName, LdapTemplate ldapTemplate);

    public List<User> getLdapUsers(LdapTemplate ldapTemplate, boolean matchGroups);

    Authentication createSuccessfulAuthentication(Authentication authentication,
                                                  UserDetails user);
}
