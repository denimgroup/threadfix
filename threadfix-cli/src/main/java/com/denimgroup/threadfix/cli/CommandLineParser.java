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
package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.commons.cli.*;

import java.util.Map;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.map;

public class CommandLineParser {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(CommandLineParser.class);

	private static ThreadFixRestClient client = new ThreadFixRestClientImpl();
	
	private static final Map<String, String[]> scanOptions = map(
		"Source Code Access Level", new String[]{ "None", "Detect", "Partial", "Full" },
		"Framework Type", new String[]{ "None", "Detect", "JSP", "Spring MVC" },
		"Repository URL", new String[]{ "Arbitrary Git URL" }
    );

	public static void main(String[] args) {

		Options options = OptionsHolder.getOptions();
		
		PosixParser parser = new PosixParser();
		try {
			CommandLine cmd = parser.parse(options, args);
			
			if (cmd.hasOption("help")) {
				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp("java -jar tfcli.jar", options );
				
			} else if (cmd.hasOption("s")) {
				
				String[] setArgs = cmd.getOptionValues("s");
				if (setArgs == null || setArgs.length != 2) {
					throw new ParseException("Bad arguments for set.");
				}
				
				if ("url".equals(setArgs[0])) {
                    LOGGER.info("Setting URL to " + setArgs[1]);
					client.setUrl(setArgs[1]);
				} else if ("key".equals(setArgs[0])) {
                    LOGGER.info("Setting API Key to " + setArgs[1]);
					client.setKey(setArgs[1]);
				} else {
					throw new ParseException("First argument to set must be url or key");
				}
			} else if (cmd.hasOption("search")) {

				String[] setArgs = cmd.getOptionValues("search");
				printOutput(VulnSearchParameterParser.processVulnerabilitySearchParameters(client, setArgs));
				
			} else if (cmd.hasOption("ct")) {
				String[] createArgs = cmd.getOptionValues("ct");
				if (createArgs.length != 1) {
					throw new ParseException("Wrong number of arguments.");
				}
                LOGGER.info("Creating a Team with the name " + createArgs[0] + ".");
                printOutput(client.createTeam(createArgs[0]));
			
			} else if (cmd.hasOption("cw")) {
				String[] createArgs = cmd.getOptionValues("cw");
				if (createArgs.length != 2) {
					throw new ParseException("Wrong number of arguments.");
				}
				LOGGER.info("Creating a Waf with the name " + createArgs[0] + ".");
                printOutput(client.createWaf(createArgs[0], createArgs[1]));
				
			} else if (cmd.hasOption("ca")) {
				String[] createArgs = cmd.getOptionValues("ca");
				if (createArgs.length != 3) {
					throw new ParseException("Wrong number of arguments.");
				}
                if (isInteger(createArgs[0])) {
                    LOGGER.info("Creating an Application with the name " + createArgs[1] + ".");
                    printOutput(client.createApplication(createArgs[0], createArgs[1], createArgs[2]));
                } else
                    LOGGER.warn("TeamId is not number, not doing anything.");

			} else if (cmd.hasOption("printScanOptions")) {
				for (Entry<String, String[]> entry : scanOptions.entrySet()) {
                    System.out.println("Options for " + entry.getKey());
					for (String option : entry.getValue()) {
                        System.out.println("\t" + option);
					}
				}
				
			} else if (cmd.hasOption("sp")) {
                String[] parameterArgs = cmd.getOptionValues("sp");
                if (! (parameterArgs.length == 2 || parameterArgs.length == 3)) {
                    throw new ParseException("Wrong number of arguments.");
                }

                // appId> <sourceCodeAccessLevel> <frameworkType> <repositoryUrl
                String
                        appId = parameterArgs[0],
                        frameworkType = parameterArgs[1],
                        repositoryUrl = null;
                if (isInteger(appId)) {
                    if (parameterArgs.length == 3) {
                        repositoryUrl = parameterArgs[2];
                    }

                    if (!appId.matches("^[0-9]+$")) {
                        throw new ParseException("Application ID must be an integer value");
                    }

                    if (!containsCaseIgnore(scanOptions.get("Framework Type"), frameworkType)) {
                        frameworkType = "DETECT";
                    } else {
                        frameworkType = upperCaseAndUnderscore(frameworkType);
                    }

                    LOGGER.info("Setting parameters for application " + appId + " to " +
                            "Framework Type: " + frameworkType);

                    // TODO return a success message instead of the (mostly irrelevant) application information.
                    printOutput(client.setParameters(appId, frameworkType, repositoryUrl));

                } else
                    LOGGER.warn("ApplicationId is not number, not doing anything.");
				
			} else if (cmd.hasOption("teams")) {
                LOGGER.info("Getting all teams.");
                printOutput(client.getAllTeams());

            } else if (cmd.hasOption("tpp")) {
                LOGGER.info("Getting all teams and applications in pretty print.");
                printOutput(client.getAllTeamsPrettyPrint());
	
			} else if (cmd.hasOption("q")) {
				String[] queueArgs = cmd.getOptionValues("q");
				if (queueArgs.length > 3) {
					throw new ParseException("Wrong number of arguments.");
				}
                if (isInteger(queueArgs[0])) {
                    LOGGER.info("Queueing a scan.");
					String scanConfigId = queueArgs.length >= 3 ? queueArgs[2] : null;
                    System.out.println(client.queueScan(queueArgs[0], queueArgs[1], scanConfigId));
                } else
                    LOGGER.warn("ApplicationId is not number, not doing anything.");

			} else if (cmd.hasOption("au")) {
				String[] addUrlArgs = cmd.getOptionValues("au");
				if (addUrlArgs.length != 2) {
					throw new ParseException("Wrong number of arguments.");
				}
                LOGGER.info("Adding url to applicationId " + addUrlArgs[0]);
				System.out.println(client.addAppUrl(addUrlArgs[0], addUrlArgs[1]));
				
			} else if(cmd.hasOption("stc")) {
				String[] setTaskConfigArgs = cmd.getOptionValues("stc");
				if(setTaskConfigArgs.length != 3) {
					throw new ParseException("Wrong number of arguments.");
				}
                if (isInteger(setTaskConfigArgs[0])) {
                    LOGGER.info("Setting task config");
                    System.out.println(client.setTaskConfig(setTaskConfigArgs[0], setTaskConfigArgs[1], setTaskConfigArgs[2]));
                } else
                    LOGGER.warn("ApplicationId is not number, not doing anything.");
			} else if (cmd.hasOption("u")) {
				String[] uploadArgs = cmd.getOptionValues("u");
				// Upload a scan
				if (uploadArgs.length != 2) {
					throw new ParseException("Wrong number of arguments.");
				}
                if (isInteger(uploadArgs[0])){
                    LOGGER.info("Uploading " + uploadArgs[1] +
                            " to Application " + uploadArgs[0] + ".");
                    printOutput(client.uploadScan(uploadArgs[0], uploadArgs[1]));
                } else
                    LOGGER.warn("ApplicationId is not number, not doing anything.");

			} else if (cmd.hasOption("st")) {
				String[] searchArgs = cmd.getOptionValues("st");
				if (searchArgs.length != 2) {
					throw new ParseException("Wrong number of arguments.");
				}
				if ("id".equals(searchArgs[0])) {
                    LOGGER.info("Searching for team with the id " + searchArgs[1] + ".");
                    printOutput(client.searchForTeamById(searchArgs[1]));
				} else if ("name".equals(searchArgs[0])) {
                    LOGGER.info("Searching for team with the name " + searchArgs[1] + ".");
                    printOutput(client.searchForTeamByName(searchArgs[1]));
				} else {
                    LOGGER.error("Unknown property argument. Try either id or name.");
				}
				
			} else if (cmd.hasOption("sw")) {
				String[] searchArgs = cmd.getOptionValues("sw");
				if (searchArgs.length != 2) {
					throw new ParseException("Wrong number of arguments.");
				}
				if ("id".equals(searchArgs[0])) {
                    LOGGER.info("Searching for WAF with the id " + searchArgs[1] + ".");
                    printOutput(client.searchForWafById(searchArgs[1]));
				} else if ("name".equals(searchArgs[0])) {
                    LOGGER.info("Searching for WAF with the name " + searchArgs[1] + ".");
                    printOutput(client.searchForWafByName(searchArgs[1]));
				} else {
					throw new ParseException("Unknown property argument. Try either id or name.");
				}
			
			} else if (cmd.hasOption("sa")) {
				String[] searchArgs = cmd.getOptionValues("sa");
				if ("id".equals(searchArgs[0])) {
					if (searchArgs.length != 2) {
						System.out.println("Wrong number of arguments.");
						return;
					}
                    if (isInteger(searchArgs[1])){
                        LOGGER.info("Searching for application with the id " + searchArgs[1] + ".");
                        System.out.println(client.searchForApplicationById(searchArgs[1]));
                    } else
                        LOGGER.warn("ApplicationId is not number, not doing anything.");
				} else if ("name".equals(searchArgs[0])) {
					if (searchArgs.length != 3) {
						System.out.println("Wrong number of arguments. You need to input application name and team name as well.");
						return;
					}
                    LOGGER.info("Searching for application with the name " + searchArgs[1] + " of team " + searchArgs[2]);
					System.out.println(client.searchForApplicationByName(searchArgs[1], searchArgs[2]));
                } else if ("uniqueId".equals(searchArgs[0])) {
                    if (searchArgs.length != 3) {
                        System.out.println("Wrong number of arguments. You need to input application uniqueId and team name as well.");
                        return;
                    }
                    LOGGER.info("Searching for application with the uniqueId " + searchArgs[1] + " of team " + searchArgs[2]);
                    System.out.println(client.searchForApplicationByUniqueId(searchArgs[1], searchArgs[2]));
				} else {
                    LOGGER.error("Unknown property argument. Try either id, uniqueId or name.");
				}
			
			} else if (cmd.hasOption("r")) {
				String[] ruleArgs = cmd.getOptionValues("r");
				if (ruleArgs.length != 1) {
					throw new ParseException("Wrong number of arguments.'");
				}
                if (isInteger(ruleArgs[0])) {
                    LOGGER.info("Downloading all rules from WAF with ID " + ruleArgs[0] + ".");
                    printOutput(client.getRules(ruleArgs[0], "-1"));
                } else
                    LOGGER.warn("WafId is not number, not doing anything.");

            } else if (cmd.hasOption("ra")) {
                String[] ruleArgs = cmd.getOptionValues("ra");
                if (ruleArgs.length != 2) {
                    throw new ParseException("Wrong number of arguments.'");
                }
                if (isInteger(ruleArgs[0])) {
                    if (isInteger(ruleArgs[1])) {
                        LOGGER.info("Downloading all rules from WAF with ID " + ruleArgs[0] + " for application with ID " + ruleArgs[1] + ".");
                        printOutput(client.getRules(ruleArgs[0], ruleArgs[1]));
                    } else {
                        LOGGER.warn("ApplicationId is not number, not doing anything.");
                    }
                } else
                    LOGGER.warn("WafId is not number, not doing anything.");

            } else {
				throw new ParseException("No arguments found.");
			}
		
		} catch (ParseException e) {
            LOGGER.error("Encountered ParseException.", e);
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("java -jar tfcli.jar", options);
		}
	}

    private static boolean isInteger(String inputStr) {
        if (inputStr == null)
            return false;
        try {
            Integer.parseInt(inputStr);
        } catch(NumberFormatException e) {
            return false;
        }
        return true;
    }

	private static <T> void printOutput(RestResponse<T> response) {

        if (response.success) {
            LOGGER.info("Operation successful, printing JSON output.");
            System.out.println(response.getOriginalJson());
        } else {
            LOGGER.error("Operation unsuccessful, printing error message.");
            if (response.message == null || response.message.trim().equals("")) {
                LOGGER.error("Invalid message received from server. Please check your URL and try again.");
                LOGGER.error("The URL should end with /rest. To set your URL, use the -s url <url> option.");
            } else {
                LOGGER.error(response.message);
            }
        }
    }
	
	private static boolean containsCaseIgnore(String[] items, String potential) {
		boolean result = false;
		
		for (String item : items) {
			if (item.equalsIgnoreCase(potential)) {
				result = true;
				break;
			}
		}
		
		return result;
	}
	
	private static String upperCaseAndUnderscore(String input) {
		return input.replace(' ', '_').toUpperCase();
	}
}
