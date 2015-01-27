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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

@Component
public class ScriptRunner {

    @Autowired
    SessionFactory sessionFactory;

    private static final SanitizedLogger LOGGER = new SanitizedLogger(ScriptRunner.class);

    /**
     *
     * @param statement sql statement
     *
     */
    @Transactional(readOnly = false) // used to be true
    public int execute(@Nonnull String statement) {

        disableConstraintChecking();
        return sessionFactory.getCurrentSession()
                .createSQLQuery(statement)
                .executeUpdate();

    }

    //    @Transactional(readOnly = false) // used to be true
    public boolean run(@Nonnull String scriptFile, @Nonnull String sqlConfigFile) {

        InputStream input = null;
        boolean isSuccess = true;
        // Create MySql Connection
        try {
            Properties prop = new Properties();
            input = new FileInputStream(sqlConfigFile);

            // load a properties file
            prop.load(input);

            Class.forName(prop.getProperty("jdbc.driverClassName"));

            Connection con = DriverManager.getConnection(
                    prop.getProperty("jdbc.url"), prop.getProperty("jdbc.username"), prop.getProperty("jdbc.password"));

            // Initialize object for ScripRunner
            com.ibatis.common.jdbc.ScriptRunner sr = new com.ibatis.common.jdbc.ScriptRunner(con, false, true);

            // Give the input file to Reader
            Reader reader = new BufferedReader(
                    new FileReader(scriptFile));

            // Exctute script
            sr.runScript(reader);

        } catch (Exception e) {
            LOGGER.error("Failed to Execute" + scriptFile
                    + " The error is " + e.getMessage());
            readErrorLog();
            isSuccess = false;

        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return isSuccess;
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


    private void readErrorLog() {
        try {
            String error = FileUtils.readFileToString(new File("error.log"));
            String detailMsg = "";
            if (error != null)
                detailMsg = " " + error.split("\\(ID")[0] + " with ID " + error.split("VALUES\\(")[1].split(",")[0] + ".";

            LOGGER.error("Unable to migrate data." + detailMsg + " Check error.log for more details.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
