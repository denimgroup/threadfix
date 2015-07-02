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

import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;

public class OptionsHolder {

    @SuppressWarnings("static-access")
    public static Options getOptions() {
        Options options = new Options();

        Option property  = OptionBuilder.withArgName( "unsafe-ssl" )
                .hasArgs(1)
                .withValueSeparator()
                .withDescription( "unsafe-ssl to force ThreadFix to accept unsigned certificates." )
                .create( "D" );
        options.addOption(property);

        Option teams = OptionBuilder.withLongOpt("teams")
                .withDescription("Fetches a list of ThreadFix teams and applications.")
                .create("t");
        options.addOption(teams);

        Option teamsPrettyPrint = OptionBuilder.withLongOpt("teamsPrettyPrint")
                .withDescription("Fetches a human readable list of ThreadFix teams, applications, and application IDs.")
                .create("tpp");
        options.addOption(teamsPrettyPrint);

        options.addOption(new Option("help", "Print this message" ));

        Option set = OptionBuilder.withArgName("property> <value")
                .hasArgs(2)
                .withLongOpt("set")
                .withDescription("Set either the url (ThreadFix base url) or key (ThreadFix API key) properties")
                .create("s");
        options.addOption(set);

        Option search = OptionBuilder
                .hasOptionalArgs()
                .withLongOpt("vulnerabilitySearch")
                .withDescription("Query the vulnerabilities using various optional parameters. More information can " +
                        "be found at https://github.com/denimgroup/threadfix/wiki/Threadfix-REST-Interface")
                .create("search");
        options.addOption(search);

        Option queueScan = OptionBuilder.withArgName("applicationId> <scannerName> <[scan profile Id]")
                .hasArgs(3)
                .withLongOpt("queueScan")
                .withDescription("Queue a scan for the given applicationId with the given scanner type")
                .create("q");
        options.addOption(queueScan);

        Option addAppUrl = OptionBuilder.withArgName("applicationId> <appUrl")
                .hasArgs(2)
                .withLongOpt("addAppUrl")
                .withDescription("Add URL for the given applicationId")
                .create("au");
        options.addOption(addAppUrl);

        Option setTaskConfig = OptionBuilder.withArgName("applicationId> <scannerName> <file")
                .hasArgs(3)
                .withLongOpt("setTaskConfig")
                .withDescription("Save the scan configuration for the given applicationId with the given scanner type")
                .create("stc");
        options.addOption(setTaskConfig);

        Option setParameters = OptionBuilder.withArgName("appId> <frameworkType> <repositoryUrl")
                .hasArgs(3)
                .withLongOpt("setParameters")
                .withDescription("Set scan parameters. Available parameters can be found with --printScanOptions")
                .create("sp");
        options.addOption(setParameters);

        options.addOption(new Option("printScanOptions", "Prints available scan options"));

        Option createTeam = OptionBuilder.withArgName("name")
                .hasArg()
                .withLongOpt("create-team")
                .withDescription("Creates a ThreadFix team and returns its JSON.")
                .create("ct");
        options.addOption(createTeam);

        Option createApp = OptionBuilder.withArgName("teamId> <name> <url")
                .hasArgs(3)
                .withLongOpt("create-app")
                .withDescription("Creates a ThreadFix application and returns its JSON.")
                .create("ca");
        options.addOption(createApp);

        Option createWaf = OptionBuilder.withArgName("name> <wafTypeName")
                .hasArgs(2)
                .withLongOpt("create-waf")
                .withDescription("Creates a ThreadFix WAF and returns its JSON.")
                .create("cw");
        options.addOption(createWaf);

        Option searchTeam = OptionBuilder.withArgName("property> <value")
                .hasArgs(2)
                .withLongOpt("search-team")
                .withDescription("Searches for a ThreadFix team and returns its JSON.")
                .create("st");
        options.addOption(searchTeam);

        Option searchWaf = OptionBuilder.withArgName("property> <value")
                .hasArgs(2)
                .withLongOpt("search-waf")
                .withDescription("Searches for a ThreadFix WAF and returns its JSON.")
                .create("sw");
        options.addOption(searchWaf);

        Option searchApp = OptionBuilder.withArgName("property> <value1> <value2")
                .hasArgs(3)
                .withLongOpt("search-app")
                .withDescription("Searches for a ThreadFix application and returns its JSON.")
                .create("sa");
        options.addOption(searchApp);

        Option upload = OptionBuilder.withArgName("appId> <file")
                .hasArgs(2)
                .withLongOpt("upload")
                .withDescription("Uploads a scan to the specified application.")
                .create("u");
        options.addOption(upload);

        Option getRules = OptionBuilder.withArgName("wafId")
                .hasArg()
                .withLongOpt("rules")
                .withDescription("Gets WAF Rules and returns its JSON.")
                .create("r");
        options.addOption(getRules);

        Option getRulesForApp = OptionBuilder.withArgName("wafId> <applicationId")
                .hasArgs(2)
                .withLongOpt("rules-for-application")
                .withDescription("Gets WAF Rules for an application and returns its JSON.")
                .create("ra");
        options.addOption(getRulesForApp);

        Option createTag = OptionBuilder.withArgName("name> <[isCommentTag]")
                .withValueSeparator(' ')
                .hasArgs(2)
                .withLongOpt("create-tag")
                .withDescription("Creates a ThreadFix Tag and returns its JSON. Set true/false for optional isCommentTag parameter.")
                .create("ctg");
        options.addOption(createTag);

        Option searchTag = OptionBuilder.withArgName("property> <value")
                .withValueSeparator(' ')
                .hasArgs(2)
                .withLongOpt("search-tag")
                .withDescription("Searches for ThreadFix Tags by either name or id, and returns their JSON.")
                .create("stg");
        options.addOption(searchTag);


        Option updateTag = OptionBuilder.withArgName("tagId> <name")
                .hasArgs(2)
                .withLongOpt("update-tag")
                .withDescription("Update ThreadFix Tag, and returns their JSON.")
                .create("utg");
        options.addOption(updateTag);


        Option removeTag = OptionBuilder.withArgName("tagId")
                .hasArgs(1)
                .withLongOpt("remove-tag")
                .withDescription("Remove ThreadFix Tag, and returns message.")
                .create("rtg");
        options.addOption(removeTag);



        Option tags = OptionBuilder.withLongOpt("tags")
                .withDescription("Fetches a list of ThreadFix tags.")
                .create("tg");
        options.addOption(tags);

        Option addAppTag = OptionBuilder.withArgName("applicationId> <tagId")
                .withValueSeparator(' ')
                .hasArgs(2)
                .withLongOpt("addAppTag")
                .withDescription("Add Tag for the given applicationId")
                .create("aat");
        options.addOption(addAppTag);

        Option removeAppTag = OptionBuilder.withArgName("applicationId> <tagId")
                .withValueSeparator(' ')
                .hasArgs(2)
                .withLongOpt("removeAppTag")
                .withDescription("Remove Tag for the given applicationId")
                .create("rat");
        options.addOption(removeAppTag);

        return options;
    }

}
