////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;

/**
 * Created by mac on 5/13/14.
 */
public abstract class AbstractNamedObjectService<T>
        extends AbstractGenericObjectService<T>
        implements GenericNamedObjectService<T> {

    public abstract GenericNamedObjectDao<T> getDao();

    @Override
    public T loadByName(String name) {
        return getDao().retrieveByName(name);
    }

    @Override
    public boolean nameExists(String name) {
        return getDao().retrieveByName(name) != null;
    }
}
