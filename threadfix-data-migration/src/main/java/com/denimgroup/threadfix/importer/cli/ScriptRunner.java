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

import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

@Component
public class ScriptRunner {

//    @Autowired
//    SessionFactory sessionFactory;
//
//    /**
//     *
//     * @param statement sql statement
//     *
//     */
//    @Transactional(readOnly = false) // used to be true
//    public void execute(@Nonnull String statement) {
//
//        disableConstraintChecking();
//        sessionFactory.getCurrentSession()
//                .createSQLQuery(statement)
//                .executeUpdate();
//
//    }

//    @Transactional(readOnly = false) // used to be true
    public void run(@Nonnull String scriptFile, @Nonnull String sqlConfigFile) {

        InputStream input = null;
// Create MySql Connection
        try {

            Properties prop = new Properties();
            input = new FileInputStream(sqlConfigFile);

            // load a properties file
            prop.load(input);

            // get the property value and print it out
            System.out.println(prop.getProperty("jdbc.driverClassName"));
            System.out.println(prop.getProperty("jdbc.url"));
            System.out.println(prop.getProperty("jdbc.username"));
            System.out.println(prop.getProperty("jdbc.password"));


            Class.forName(prop.getProperty("jdbc.driverClassName"));

            Connection con = DriverManager.getConnection(
                    prop.getProperty("jdbc.url"), prop.getProperty("jdbc.username"), prop.getProperty("jdbc.password"));

            // Initialize object for ScripRunner
            com.ibatis.common.jdbc.ScriptRunner sr = new com.ibatis.common.jdbc.ScriptRunner(con, false, false);

            // Give the input file to Reader
            Reader reader = new BufferedReader(
                    new FileReader(scriptFile));

            // Exctute script
            sr.runScript(reader);

        } catch (Exception e) {
            System.err.println("Failed to Execute" + scriptFile
                    + " The error is " + e.getMessage());
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


//    @Transactional(readOnly = false)
//    public void disableConstraintChecking() {
//        sessionFactory.getCurrentSession()
//                .createSQLQuery("SET FOREIGN_KEY_CHECKS=0;\n")
//                .executeUpdate();
//    }
//
//    @Transactional(readOnly = false)
//    public void enableConstraintChecking() {
//        sessionFactory.getCurrentSession()
//                .createSQLQuery("SET FOREIGN_KEY_CHECKS=1;\n")
//                .executeUpdate();
//    }


}
