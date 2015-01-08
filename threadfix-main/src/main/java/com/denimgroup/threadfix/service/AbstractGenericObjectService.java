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

import com.denimgroup.threadfix.data.dao.GenericObjectDao;
import com.denimgroup.threadfix.data.entities.AuditableEntity;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Created by mac on 5/13/14.
 */
public abstract class AbstractGenericObjectService<T> implements GenericObjectService<T> {

    abstract GenericObjectDao<T> getDao();

    @Override
    public T loadById(int id) {
        return getDao().retrieveById(id);
    }

    @Override
    @Transactional
    public List<T> loadAllActive() {
        return getDao().retrieveAllActive();
    }

    @Override
    public List<T> loadAll() {
        return getDao().retrieveAllActive();
    }

    @Override
    public void saveOrUpdate(T object) {
        getDao().saveOrUpdate(object);
    }

    @Override
    public void markInactive(T object) {
        if (!(object instanceof AuditableEntity)) {
            throw new IllegalArgumentException("This method should only be used with subclasses of AuditableEntity");
        }

        ((AuditableEntity) object).setActive(false);

        saveOrUpdate(object);
    }
}
