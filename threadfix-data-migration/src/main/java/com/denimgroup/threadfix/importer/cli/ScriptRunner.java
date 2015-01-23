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

package com.denimgroup.threadfix.importer.cli;

import org.apache.commons.io.FileUtils;
import org.hibernate.SessionFactory;
import org.hibernate.classic.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.io.File;
import java.io.IOException;

@Component
public class ScriptRunner {

//    @PersistenceContext
//    EntityManager entityManager;
    @Autowired
    SessionFactory sessionFactory;

    /**
     *
     * @param statement sql statement
     *
     */
    @Transactional(readOnly = false) // used to be true
    public void execute(@Nonnull String statement) {

//        sessionFactory.getCurrentSession()
//                .createSQLQuery(statement)
//                .executeUpdate();
        disableConstraintChecking();
        System.out.println(sessionFactory.getCurrentSession()
//                .createSQLQuery("BEGIN SET FOREIGN_KEY_CHECKS=0;\n" + statement + "SET FOREIGN_KEY_CHECKS=1;\n END;")
                .createSQLQuery(statement)
                .executeUpdate());
//        try {
//            Query q =  entityManager.createNativeQuery("BEGIN " + FileUtils.readFileToString(new File(filePath)) + " END;");
//            q.executeUpdate();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }

    }

    @Transactional(readOnly = false)
    public void disableConstraintChecking() {
        sessionFactory.getCurrentSession()
                .createSQLQuery("SET FOREIGN_KEY_CHECKS=0;\n")
                .executeUpdate();
    }

    @Transactional(readOnly = false)
    public void enableConstraintChecking() {
        sessionFactory.getCurrentSession()
                .createSQLQuery("SET FOREIGN_KEY_CHECKS=1;\n")
                .executeUpdate();
    }


}
