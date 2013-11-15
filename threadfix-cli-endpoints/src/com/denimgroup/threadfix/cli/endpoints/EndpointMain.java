package com.denimgroup.threadfix.cli.endpoints;

import java.io.File;
import java.util.Collections;
import java.util.List;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;

public class EndpointMain {
	
	public static void main(String[] args) {
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
		
		EndpointDatabase database = EndpointDatabaseFactory.getDatabase(rootFile);

		List<Endpoint> endpoints = database.generateEndpoints();
		
		Collections.sort(endpoints);
		
		if (endpoints.isEmpty()) {
			System.out.println("No endpoints were found.");
		} else {
			for (Endpoint endpoint : endpoints) {
				System.out.println(endpoint.getCSVLine());
			}
		}
	}
}
