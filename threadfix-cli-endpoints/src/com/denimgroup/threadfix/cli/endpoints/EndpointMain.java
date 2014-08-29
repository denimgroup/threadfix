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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EndpointMain {

    enum Logging {
        ON, OFF
    }

    static Logging logging = Logging.OFF;
	
	public static void main(String[] args) {

		if (args.length == 0 || args.length > 2) {
            printError();

        } else if (args.length == 1) {
            resetLoggingConfiguration();

            processFile(args[0]);
        } else if (args.length == 2) {
            logging = Logging.ON;

            resetLoggingConfiguration();

            if (args[0].equals("-debug")) {
                processFile(args[1]);
            } else if (args[1].equals("-debug")) {
                processFile(args[0]);
            } else {
                printError();
            }
        }
	}

    static void printError() {
        System.out.println("This program takes 1 argument, the file root.");
    }

    static void processFile(String arg) {
        File rootFile = new File(arg);

        if (!rootFile.exists()) {
            System.out.println("The root file didn't exist.");
        } else {
            listEndpoints(rootFile);
        }
    }

    private static void listEndpoints(File rootFile) {

        List<Endpoint> endpoints = new ArrayList<>();

        EndpointDatabase database = EndpointDatabaseFactory.getDatabase(rootFile);

        if (database != null) {
            endpoints = database.generateEndpoints();
        }

		Collections.sort(endpoints);
		
		if (endpoints.isEmpty()) {
			System.out.println("No endpoints were found.");
		} else {
			for (Endpoint endpoint : endpoints) {
				System.out.println(endpoint.getCSVLine());
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
            console.setThreshold(Level.INFO);
        }

        console.activateOptions();
        Logger.getRootLogger().removeAllAppenders();
        Logger.getRootLogger().addAppender(console);
    }
}
