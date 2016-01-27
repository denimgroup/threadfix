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

package com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure;

import javax.xml.bind.annotation.*;
import java.util.List;

/**
 * Created by stran on 3/14/14.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Users")
public class Users {

    @XmlElement(name="User")
    List<User> users;

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class User {

        @XmlAttribute(name = "Name")
        String name;
        @XmlAttribute(name = "FullName")
        String fullName;

        @XmlElement(name="UserActive")
        boolean userActive;

        public boolean isUserActive() {
            return userActive;
        }

        public void setUserActive(boolean userActive) {
            this.userActive = userActive;
        }
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getFullName() {
            return fullName;
        }

        public void setFullName(String fullName) {
            this.fullName = fullName;
        }
    }

}
