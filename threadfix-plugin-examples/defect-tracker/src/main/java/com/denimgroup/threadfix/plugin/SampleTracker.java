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
package com.denimgroup.threadfix.plugin;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.viewmodels.DefectMetadata;
import com.denimgroup.threadfix.viewmodels.ProjectMetadata;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * You can implement only parts of this class and have functional integration.
 *
 * If you assume valid input, return true from all three hasValid... methods.
 *
 * Static options can be used in getProjectMetadata, just expand on the code that's already there.
 * Not all of the fields need to be implemented.
 *
 * getBugUrl is purely for convenience when viewing the defect page.
 *
 * createDefect() is the most important. If you only need to export, just implement that.
 *
 * getMultipleDefectStatus is only necessary if you want changes to appear in ThreadFix.
 *
 */
public class SampleTracker extends AbstractDefectTracker {

    @Override
    public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        String id = "TEST-1";

        log.info("Creating Defect.");

        // In this method, you'll want to construct whatever message you want in the Defect Tracker
        // using information from the vulnerabilities

        StringBuilder message = new StringBuilder();

        message.append(metadata.getPreamble());

        for (Vulnerability vulnerability : vulnerabilities) {
            message.append("Found vulnerability with type ")
                    .append(vulnerability.getGenericVulnerability().getName())
                    .append(" at location ")
                    .append(vulnerability.getSurfaceLocation().getPath())
                    .append(" with parameter ")
                    .append(vulnerability.getSurfaceLocation().getParameter());
        }

        // Then you'll want to construct your request to your tracker using the metadata bean
        // something like this, although probably not all of these will apply
        Map<String, String> bugHash = new HashMap<>();
        bugHash.put("title", metadata.getDescription());
        bugHash.put("details", message.toString());
        bugHash.put("severity", metadata.getSeverity());
        bugHash.put("component", metadata.getComponent());
        bugHash.put("product", getProjectId());
        bugHash.put("priority", metadata.getPriority());
        bugHash.put("version", metadata.getVersion());
        bugHash.put("status", metadata.getStatus());

        boolean failure = false;

        // Submit to your tracker using whatever method you need.
        // XML-RPC and JSON REST examples are in BugzillaDefectTracker and JiraDefectTracker respectively.

        if (failure) {
            // Throwing a subclass of RestException will display an error message to the user
            throw new IllegalStateRestException("This message will display in the UI.");
        }

        // Return the resulting id from the tracker
        return id;
    }

    @Override
    public String getBugURL(String endpointURL, String bugID) {
        // Here you want to return the URL that points to the bug page. Something like
        // return endpointURL + "/xmlrpc.cgi?bugId=" + bugID;

        log.info("Returning the Bug URL.");

        return null;
    }

    @Override
    public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
        Map<Defect, Boolean> statusMap = new HashMap<>();

        log.info("Updating bug statuses.");

        // Find the open or closed status for each defect.
        for (Defect defect : defectList) {
            if (defect != null) {
                // code to get the status
                statusMap.put(defect, true); // whether the defect is open or closed
                defect.setStatus("Actual Status"); // ASSIGNED / RESOLVED / CLOSED / etc.
                // This will be displayed as the status for the defect
            }
        }

        return statusMap;
    }

    @Override
    public List<Defect> getDefectList() {
        return null;
    }

    @Nonnull
    @Override
    public List<String> getProductNames() {
        log.info("Getting list of product names.");

        // In this method you will have a username and password that the user configured as well as
        // the endpoint URL that was previously configured. These can be accessed with

        String usernameToSubmit = getUsername();
        String passwordToSubmit = getPassword();
        String urlToUse = getUrl();

        // Do whatever to get the product names, then concatenate them together with commas separating them

        // If you use the setLastError method and return null,
        // the user will be presented with the passed string as an error message.
        setLastError("The request for product names failed because the credentials are incorrect.");

        return list("some", "product", "names");
    }

    @Override
    public String getProjectIdByName() {
        // In this method, in addition to getUsername(), getPassword(), and getUrl(),
        // getProjectName() should return a valid product name.
        // Your job is to use this information to find the corresponding ID.
        // If you do not have separate names and IDs, just use the name.

        // maybe do web requests

        log.info("Finding id for project " + getProjectName());

        return "internal ID";
    }

    @Override
    public ProjectMetadata getProjectMetadata() {
        log.info("Collecting project metadata");

        // This method is a little trickier than the previous ones.
        // You will have username, password, url, projectname, and projectid.
        // either make a request or populate lists in code and return a ProjectMetadata object.
        // The values you present here are options that the user will select that will then come back
        // in the defectmetadata object for createDefect().

        List<String> statuses = new ArrayList<String>();
        List<String> components = new ArrayList<String>();
        List<String> severities = new ArrayList<String>();
        List<String> versions = new ArrayList<String>();
        List<String> priorities = new ArrayList<String>();


        // Something like this should get you started
        // if you want to dynamically populate these there are examples for JIRA and Bugzilla in those classes.
        statuses.add("New");
        statuses.add("Confirmed");

        components.add("TestComponent");
        components.add("ThreadFix");

        severities.add("Critical");
        severities.add("Medium");

        versions.add("1");
        versions.add("2");

        priorities.add("P1");
        priorities.add("P2");

        return new ProjectMetadata(components, versions,
                severities, statuses, priorities);
    }

    @Override
    public boolean hasValidCredentials() {
        // getUrl(), getPassword(), and getUsername will give values here.
        // Given those, check the credentials for validity.
        log.info("Checking credentials.");
        return true;
    }

    @Override
    public boolean hasValidProjectName() {
        // getProjectName() as well as credentials and the URL are available here.
        // this is used to check server-side that the user picked a valid option from the drop-down.
        log.info("Checking Project Name.");
        return true;
    }

    @Override
    public boolean hasValidUrl() {
        // Given only getUrl(), make sure that there is a valid endpoint that you can use.
        log.info("Checking URL.");
        return true;
    }
}
