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

package com.denimgroup.threadfix.update.hsql;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class HSQLDriver {

	public static Connection conn;

    public HSQLDriver(String dbFileNamePrefix, String username, String password)
    		throws Exception {

        Class.forName("org.hsqldb.jdbcDriver");

        conn = DriverManager.getConnection("jdbc:hsqldb:" + dbFileNamePrefix,
        		username,                     // username
        		password);                    // password
    }

    public void shutdown() throws SQLException {
        Statement statement = conn.createStatement();

        statement.execute("SHUTDOWN");
        conn.close();
    }

    public void update(String expression) throws SQLException {
    	if (expression != null && expression.length() >= 2 && !expression.startsWith("--")) {
    		Statement st = null;

            st = conn.createStatement();

            int i = st.executeUpdate(expression);

            if (i == -1) {
                System.out.println("db error : " + expression);
            }

            st.close();
    	}
    }

    public static void main(String[] args) {

    	HSQLDriver db = null;
    	
    	String dbPrefix = null, username = null, password = null;
    	
    	if (args.length == 3) {
    		dbPrefix = args[0];
    		username = args[1];
    		password = args[2];
    		if (password.equals("emptyPassword")) {
    			password = "";
    		}
    	} else {
    		System.out.println("Proper argument syntax is databaseFilePath username password");
    		return;
    	}

        try {
            db = new HSQLDriver(dbPrefix, username, password);
        } catch (Exception ex1) {
            ex1.printStackTrace();
            return;
        }
        
        try {
	        if (!tablesExist("DELETEDCLOSEMAP")) {
	        	System.out.println("DELETEDCLOSEMAP table not found. Adding appropriate tables.");
	        	db.runSQLFile("deleted.sql");
	        } else {
	        	System.out.println("DELETEDCLOSEMAP already present. Continuing.");
	        }
	        	
	        if (!tablesExist("ACCESSCONTROLAPPLICATIONMAP")) {
	        	System.out.println("ACCESSCONTROLAPPLICATIONMAP table not found. Running 1.0.1 -> 1.1 SQL file.");
	        	db.runSQLFile("update.sql");
	        } else {
	        	System.out.println("1.1 tables are present, not running update.sql.");
	        }
	        
	        if (!channelExists("IBM Rational AppScan Enterprise")) {
	        	System.out.println("IBM Rational AppScan Enterprise channel type not found. Running AppScan SQL file.");
	        	db.runSQLFile("appscan-enterprise.sql");
	        } else {
	        	System.out.println("IBM Rational AppScan Enterprise is present, not running appscan-enterprise.sql.");
	        }
	        
	        // 1.1 final
	        if (!channelVulnExists("Remote Code Execution", "Brakeman")) {
	        	System.out.println("New Brakeman types not found. Running brakeman.sql.");
	        	db.runSQLFile("brakeman.sql");
	        } else {
	        	System.out.println("New Brakeman types are present, not running brakeman.sql.");
	        }
	        
	    	// 1.2rc2
	        if (!channelVulnExists("Reflected Cross-site scripting (XSS)", "NTO Spider")) {
	        	System.out.println("NTO 6 mappings not found. Running NTO 6 upgrade script.");
	        	db.runSQLFile("nto6.sql");
	        } else {
	        	System.out.println("NTO 6 mappings are present, not running nto6.sql.");
		    }
	        
	        // 1.2rc3
	        if (!channelExists("Dependency Check")) {
	        	System.out.println("Dependency Check not found. Running 1_2rc3.sql.");
	        	db.runSQLFile("1_2rc3.sql");
	        } else {
	        	System.out.println("Dependency Check is present, not running 1_2rc3.sql.");
	        }
	        
	        // 1.2final
	        if (!channelVulnExists("Business Logic Errors", "Veracode")) {
	        	System.out.println("1.2 Final vulnerabilities not found, running rc3-final.sql");
	        	db.runSQLFile("rc3-final.sql");
	        } else {
	        	System.out.println("1.2 Final vulnerabilities were found, not running rc3-final.sql.");
		    }
	        
        } finally {
        
	        // Shut it down
	        try {
	        	System.out.println("All done. Closing connection and exiting.");
				db.shutdown();
			} catch (SQLException e) {
				System.out.println("Unable to close database connection.");
				e.printStackTrace();
			}
        }
    }
    
    public static boolean channelVulnExists(String vulnName, String scannerName) {
    	ResultSet set = getResults("SELECT * FROM CHANNELVULNERABILITY WHERE NAME = '" + vulnName +
    			"' AND CHANNELTYPEID = (SELECT ID FROM CHANNELTYPE WHERE NAME = '" + scannerName + "');");
    	
    	try {
			return set != null && set.next();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}

	public static boolean tablesExist(String... tableNames) {
	    try {
	    	DatabaseMetaData meta = conn.getMetaData();
	    	ResultSet res = meta.getTables(null, null, null,
	    			new String[] {"TABLE"});
	    	
	    	List<String> strings = new ArrayList<String>();
	    	while (res.next()) {
	    		strings.add(res.getString("TABLE_NAME").toLowerCase());
	    	}
	    	
	    	for (String table : tableNames) {
	    		if (!strings.contains(table.toLowerCase())) {
	    			return false;
	    		}
	    	}
	    	
	    	return true;
	    	
	    } catch (SQLException e) {
	    	e.printStackTrace();
	    }
    	
    	return false;
    }
	
	public static ResultSet getResults(String query) {
		try {
    		PreparedStatement statement = conn.prepareStatement(query);
    		
    		ResultSet set = statement.executeQuery();
    		
    		return set;
    		
    	} catch (SQLException e) {
    		e.printStackTrace();
    	}
    	
    	return null;
	}
    
    public static boolean channelExists(String scannerName) {
    	ResultSet set = getResults("SELECT * FROM CHANNELTYPE WHERE NAME = '" + scannerName + "';");
		try {
			return set != null && set.next();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
    }
    
    public void runSQLFile(String file) {
    	BufferedReader reader = null;
        
        try {
			reader = new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
        
        List<String> statements = new ArrayList<String>();
        
        try {
			while (reader.ready()) {
				statements.add(reader.readLine());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

        try {
        	for (String statement : statements) {
        		update(statement);
        	}
        } catch (SQLException ex3) {
            ex3.printStackTrace();
        }
    }

	
}