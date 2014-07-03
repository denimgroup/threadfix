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
	
	public static void main(String[] args) {

        resetLoggingConfiguration();

		if (args.length != 1) {
			System.out.println("This program takes 1 argument, the file root.");
			
		} else {
		
			File rootFile = new File(args[0]);
			
			if (!rootFile.exists()) {
				System.out.println("The root file didn't exist.");
			} else {
				listEndpoints(rootFile);
			}
		}
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
				System.out.println(endpoint.getCSVLine());
			}
		}
	}

    private static void resetLoggingConfiguration() {
        ConsoleAppender console = new ConsoleAppender(); //create appender
        String pattern = "%d [%p|%c|%C{1}] %m%n";
        console.setLayout(new PatternLayout(pattern));
        console.setThreshold(Level.FATAL);
        console.activateOptions();
        Logger.getRootLogger().addAppender(console);
    }
}
