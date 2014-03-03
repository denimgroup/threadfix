package com.denimgroup.threadfix.selenium.utils;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;

/**
 * Created by mac on 3/3/14.
 */
public class DatabaseUtils {

    public static final String DRIVER_NAME, URL, USERNAME, PASSWORD;
    private static final Connection dbConnection;

    static {
        Properties prop = new Properties();

        try (InputStream input = DatabaseUtils.class.getClassLoader().getResourceAsStream("jdbc.properties")) {

            // load a properties file
            prop.load(input);

            // get the property value and print it out
            DRIVER_NAME = prop.getProperty("jdbc.driverClassName");
            URL         = prop.getProperty("jdbc.url");
            USERNAME    = prop.getProperty("jdbc.username");
            PASSWORD    = prop.getProperty("jdbc.password");

            if (DRIVER_NAME == null) {
                throw new IllegalStateException("Please set jdbc.driverClassName in jdbc.properties");
            }
            if (URL == null) {
                throw new IllegalStateException("Please set jdbc.url in jdbc.properties");
            }
            if (USERNAME == null) {
                throw new IllegalStateException("Please set jdbc.username in jdbc.properties");
            }
            if (PASSWORD == null) {
                throw new IllegalStateException("Please set jdbc.password in jdbc.properties");
            }

            Class.forName(DRIVER_NAME);

            dbConnection =
                    DriverManager.getConnection(URL, USERNAME, PASSWORD);

        } catch (IOException | ClassNotFoundException | SQLException ex) {
            throw new IllegalStateException("IOException encountered on initialization", ex);
        }
    }

    public static void createTeam(String teamName) {
        try {
            PreparedStatement statement = dbConnection.prepareCall("INSERT INTO ORGANIZATION (name, active, createdDate, modifiedDate) VALUES (?, true, NOW(), NOW());");
            statement.setString(1, teamName);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("IOException encountered on initialization", e);
        }
    }

    public static void createApplication(String teamName, String appName) {
        throw new UnsupportedOperationException("Haven't implemented this yet.");
    }

}
