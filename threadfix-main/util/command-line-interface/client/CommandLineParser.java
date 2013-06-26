package com.denimgroup.threadfix.client;


public class CommandLineParser {
	
	public static ThreadFixRestClient client = new ThreadFixRestClient();

	public static void main (String [] args) {
		if (args.length == 0) {
			System.out.println("Please enter a valid command (set, create, search, upload, rules).");
		} else {
			// Settings
			if ("set".equals(args[0])) {
				if (args.length != 3) {
					System.out.println("Please enter two arguments for set: the property (url, key) and the value.");
					return;
				}
				
				if ("url".equals(args[1])) {
					System.out.println("Setting URL to " + args[2]);
					client.setUrl(args[2]);
				} else if ("key".equals(args[1])) {
					System.out.println("Setting API Key to " + args[2]);
					client.setKey(args[2]);
				}

			} else if ("create".equals(args[0]) || "c".equals(args[0])) {
				// Create stuff
				if (args.length == 1) {
					System.out.println("You need to specify what to create.");
					return;
				} else if ("team".equals(args[1]) || "t".equals(args[1])) {
					if (args.length != 3) {
						System.out.println("Wrong number of arguments. Please enter 'create team {teamName}'");
						return;
					}
					System.out.println("Creating a Team with the name " + args[2] + ".");
					System.out.println(client.createTeam(args[2]));
				} else if ("waf".equals(args[1]) || "w".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'create waf {name} {type}'");
						return;
					}
					System.out.println("Creating a Waf with the name " + args[2] + ".");
					System.out.println(client.createWaf(args[2], args[3]));
				} else if ("app".equals(args[1]) || "application".equals(args[1]) || "a".equals(args[1])) {
					if (args.length != 5) {
						System.out.println("Wrong number of arguments. Please enter 'create application {teamId} {name} {url}'");
						return;
					}
					System.out.println("Creating an Application with the name " + args[3] + ".");
					System.out.println(client.createApplication(args[2], args[3], args[4]));
				} else if ("app-channel".equals(args[1]) || "application-channel".equals(args[1]) || "ac".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'create application-channel {appId} {channelType}'");
						return;
					}
					System.out.println("Creating an Application Channel for Application " + args[2] + 
							" and channel type " + args[3] + ".");
					System.out.println(client.addApplicationChannel(args[2], args[3]));
				} else {
					System.out.println("Unexpected object type. Try team, waf, application, or application-channel.");
				}
				
			} else if ("search".equals(args[0]) || "s".equals(args[0])) {
				// Search for objects
				if (args.length < 2) {
					System.out.println("You need to specify what to search for.");
					return;
				}

				if ("team".equals(args[1]) || "t".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'search team (name {name} || id {id})'");
						return;
					}
					if ("id".equals(args[2])) {
						System.out.println("Searching for team with the id " + args[3] + ".");
						System.out.println(client.searchForTeamById(args[3]));
					} else if ("name".equals(args[2])) {
						System.out.println("Searching for team with the name " + args[3] + ".");
						System.out.println(client.searchForTeamByName(args[3]));
					} else {
						System.out.println("Unknown third argument. Try either id or name.");
						return;
					}
				} else if ("waf".equals(args[1]) || "w".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'search waf (name {name} || id {id})'");
						return;
					}
					if ("id".equals(args[2])) {
						System.out.println("Searching for WAF with the id " + args[3] + ".");
						System.out.println(client.searchForWafById(args[3]));
					} else if ("name".equals(args[2])) {
						System.out.println("Searching for WAF with the name " + args[3] + ".");
						System.out.println(client.searchForWafByName(args[3]));
					} else {
						System.out.println("Unknown third argument. Try either id or name.");
						return;
					}
				} else if ("application".equals(args[1]) || "app".equals(args[1]) || "a".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'search application (name {name} || id {id})'");
						return;
					}
					if ("id".equals(args[2])) {
						System.out.println("Searching for team with the id " + args[3] + ".");
						System.out.println(client.searchForApplicationById(args[3]));
					} else if ("name".equals(args[2])) {
						System.out.println("Searching for team with the name " + args[3] + ".");
						System.out.println(client.searchForApplicationByName(args[3]));
					} else {
						System.out.println("Unknown third argument. Try either id or name.");
						return;
					}
				} else if ("app-channel".equals(args[1]) || "application-channel".equals(args[1]) || "ac".equals(args[1])) {
					if (args.length != 4) {
						System.out.println("Wrong number of arguments. Please enter 'search application-channel {appId} {channelType}'");
						return;
					}
					System.out.println("Searching for an Application Channel for Application " + args[2] + 
							" and channel type " + args[3] + ".");
					System.out.println(client.searchForApplicationChannel(args[2], args[3]));
				} else {
					System.out.println("Unexpected object type. Try team, waf, application, or application-channel.");
				}
				
			} else if ("upload".equals(args[0]) || "u".equals(args[0])) {
				// Upload a scan
				if (args.length != 3) {
					System.out.println("Wrong number of arguments. Please enter 'upload {channelId} {filePath}'");
					return;
				}
				System.out.println("Uploading " + args[2] + 
						" to Application Channel " + args[1] + ".");
				System.out.println(client.uploadScan(args[1], args[2]));
				
			} else if ("rules".equals(args[0]) || "r".equals(args[0])) {
				// Generate / pull WAF rules
				if (args.length != 2) {
					System.out.println("Wrong number of arguments. Please enter 'rules {wafId}'");
					return;
				}
				System.out.println("Downloading rules from WAF with ID " + args[1] + ".");
				System.out.println(client.getRules(args[1]));
			} else {
				System.out.println("Unknown command. Try one of set, create, search, upload, rules.");
			}
		}
	}
	
}
