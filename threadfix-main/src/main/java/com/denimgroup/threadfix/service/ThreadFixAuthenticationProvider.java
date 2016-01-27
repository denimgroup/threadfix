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

import com.denimgroup.threadfix.data.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ThreadFixAuthenticationProvider extends DaoAuthenticationProvider {

    @Autowired
    private UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication successAuthentication = super.authenticate(authentication);

        if (successAuthentication != null) {
            if (successAuthentication.getPrincipal() instanceof ThreadFixUserDetails) {
                Integer userId = ((ThreadFixUserDetails) successAuthentication.getPrincipal()).getUserId();
                User user = userService.loadUser(userId);
                String presentedPassword = String.valueOf(successAuthentication.getCredentials());

                if ((user != null) && (presentedPassword != null) && !presentedPassword.trim().equals("")) {
                    ThreadFixPasswordEncoder threadFixPasswordEncoder = (ThreadFixPasswordEncoder)getPasswordEncoder();
                    if (threadFixPasswordEncoder.isPasswordLegacyEncoded(user)
                            || (threadFixPasswordEncoder.isPasswordEncodingStrengthBelowConfiguration(user)) ) {
                        user.setUnencryptedPassword(presentedPassword);
                        userService.storeUser(user);
                    }
                }
            }
        }

        return successAuthentication;
    }
}
