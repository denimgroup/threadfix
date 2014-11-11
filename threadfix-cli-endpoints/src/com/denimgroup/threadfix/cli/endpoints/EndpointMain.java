////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.cli.endpoints;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

import java.io.File;
import java.util.Collections;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class EndpointMain {

    enum Logging {
        ON, OFF
    }

    static Logging              logging     = Logging.OFF;
    static Endpoint.PrintFormat printFormat = Endpoint.PrintFormat.DYNAMIC;

    public static void main(String[] args) {
        if (checkArguments(args)) {
            resetLoggingConfiguration();
            listEndpoints(new File(args[0]));
        } else {
            printError();
        }
    }

    private static boolean checkArguments(String[] args) {
        if (args.length == 0) {
            return false;
        }

        File rootFile = new File(args[0]);

        if (rootFile.exists() && rootFile.isDirectory()) {

            List<String> strings = list(args);

            strings.remove(0);

            for (String string : strings) {
                if (string.equals("-debug")) {
                    logging = Logging.ON;
                } else if (string.equals("-lint")) {
                    printFormat = Endpoint.PrintFormat.LINT;
                } else {
                    System.out.println("Received unsupported option " + string + ", valid arguments are -lint and -debug");
                    return false;
                }
            }

            return true;

        } else {
            System.out.println("Please enter a valid file path as the first parameter.");
        }

        return false;
    }

    static void printError() {
        System.out.println("The first argument should be a valid file path to scan. Other flags supported: -lint, -debug");
    }

    private static void listEndpoints(File rootFile) {

        List<Endpoint> endpoints = list();

        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(rootFile);

        if (database != null) {
            endpoints = database.generateEndpoints();
        }

		Collections.sort(endpoints);
		
		if (endpoints.isEmpty()) {
			System.out.println("No endpoints were found.");
		} else {
			for (Endpoint endpoint : endpoints) {
				System.out.println(endpoint.getCSVLine(printFormat));
			}
		}

        System.out.println("To enable logging include the -debug argument");
    }

    private static void resetLoggingConfiguration() {
        ConsoleAppender console = new ConsoleAppender(); //create appender
        String pattern = "%d [%p|%c|%C{1}] %m%n";
        console.setLayout(new PatternLayout(pattern));

        if (logging == Logging.ON) {
            console.setThreshold(Level.DEBUG);
        } else {
            console.setThreshold(Level.ERROR);
        }

        console.activateOptions();
        Logger.getRootLogger().removeAllAppenders();
        Logger.getRootLogger().addAppender(console);
    }
}
