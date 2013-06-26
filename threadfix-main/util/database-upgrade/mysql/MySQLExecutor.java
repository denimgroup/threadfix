package com.denimgroup.threadfix.update;

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

/**
 * This file needs only system libraries and the mysql connector JAR to compile.
 * Be sure to also have the following files available
 *   deleted.sql
 *   update.sql
 *   appscan-enterprise.sql
 *   brakeman.sql
 * 
 * 
 * @author mcollins
 */
public class MySQLExecutor {

    public static Connection conn;

    public MySQLExecutor(String dbFileNamePrefix, String username, String password)
    		throws Exception {

    	Class.forName("com.mysql.jdbc.Driver");

        conn = DriverManager.getConnection("jdbc:mysql:" + dbFileNamePrefix,
        		username,                     // username
        		password);                    // password
    }

    public void shutdown() throws SQLException {
        conn.close();
    }

    public void update(String expression) throws SQLException {

        Statement st = null;

        st = conn.createStatement();

        int i = st.executeUpdate(expression);

        if (i == -1) {
            System.out.println("db error : " + expression);
        }

        st.close();
    }

    public static void main(String[] args) {

    	MySQLExecutor db = null;
    	
    	String dbPrefix = null, username = null, password = null;
    	
    	if (args.length == 3) {
    		dbPrefix = args[0];
    		username = args[1];
    		password = args[2];
    		if (password.equals("emptyPassword")) {
    			password = "";
    		}
    	} else {
    		System.out.println("Proper argument syntax is database-URL username password");
    		return;
    	}

        try {
            db = new MySQLExecutor(dbPrefix, username, password);
        } catch (Exception ex1) {
            ex1.printStackTrace();
            return;
        }
        
        if (!tablesExist("DeletedCloseMap")) {
        	System.out.println("DeletedCloseMap table not found. Adding appropriate tables.");
        	db.runSQLFile("deleted.sql");
        } else {
        	System.out.println("DeletedCloseMap already present. Continuing.");
        }
        	
        if (!tablesExist("AccessControlApplicationMap")) {
        	System.out.println("AccessControlApplicationMap table not found. Running 1.0.1 -> 1.1 SQL file.");
        	db.runSQLFile("update.sql");
        } else {
        	System.out.println("1.1 tables are present, not running update.sql.");
        }
        
        try {
	        if (!channelExists("IBM Rational AppScan Enterprise")) {
	        	System.out.println("IBM Rational AppScan Enterprise channel type not found. Running AppScan SQL file.");
	        	db.runSQLFile("appscan-enterprise.sql");
	        } else {
	        	System.out.println("IBM Rational AppScan Enterprise is present, not running appscan-enterprise.sql.");
	        }
        } catch (SQLException e) {
        	System.out.println("Something went wrong trying to run AppScan Enterprise updates.");
        }
        
        if (!newBrakemanInsertsExist()) {
        	System.out.println("New Brakeman types not found. Running brakeman.sql.");
        	db.runSQLFile("brakeman.sql");
        } else {
        	System.out.println("New Brakeman types are present, not running brakeman.sql.");
	    }
        
        // Shut it down
        try {
        	System.out.println("All done. Closing connection and exiting.");
			db.shutdown();
		} catch (SQLException e) {
			System.out.println("Unable to close database connection.");
			e.printStackTrace();
		}
    }
    
    public static boolean channelExists(String scannerName) throws SQLException {
		PreparedStatement statement = conn.prepareStatement("SELECT * FROM ChannelType WHERE name = '" + scannerName + "';");
		
		ResultSet set = statement.executeQuery();
		
		if (set != null) {
			return set.next();
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
    
    public static boolean newBrakemanInsertsExist() {
    	ResultSet set = getResults("SELECT * FROM ChannelVulnerability WHERE name = 'Remote Code Execution' AND channelTypeId = (SELECT id FROM ChannelType WHERE name = 'Brakeman');");
    	
    	try {
			return set != null && set.next();
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
				String statement = reader.readLine();
				if (!statement.trim().isEmpty())
					statements.add(statement);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

        String lastStatement = null;
        try {
        	for (String statement : statements) {
        		lastStatement = statement;
        		update(statement);
        	}
        } catch (SQLException ex3) {
        	System.out.println(lastStatement);
            ex3.printStackTrace();
        }
    }
}
