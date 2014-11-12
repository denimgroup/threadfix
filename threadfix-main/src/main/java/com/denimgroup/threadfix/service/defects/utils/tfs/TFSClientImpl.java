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
package com.denimgroup.threadfix.service.defects.utils.tfs;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.exception.DefectTrackerUnavailableException;
import com.denimgroup.threadfix.importer.util.ResourceUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ProxyService;
import com.denimgroup.threadfix.service.defects.TFSDefectTracker;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;
import com.microsoft.tfs.core.TFSTeamProjectCollection;
import com.microsoft.tfs.core.clients.workitem.WorkItem;
import com.microsoft.tfs.core.clients.workitem.WorkItemClient;
import com.microsoft.tfs.core.clients.workitem.fields.*;
import com.microsoft.tfs.core.clients.workitem.project.Project;
import com.microsoft.tfs.core.clients.workitem.project.ProjectCollection;
import com.microsoft.tfs.core.clients.workitem.query.WorkItemCollection;
import com.microsoft.tfs.core.config.ConnectionAdvisor;
import com.microsoft.tfs.core.config.DefaultConnectionAdvisor;
import com.microsoft.tfs.core.exceptions.TECoreException;
import com.microsoft.tfs.core.exceptions.TFSUnauthorizedException;
import com.microsoft.tfs.core.httpclient.Credentials;
import com.microsoft.tfs.core.httpclient.UsernamePasswordCredentials;
import com.microsoft.tfs.core.httpclient.auth.AuthScope;
import com.microsoft.tfs.core.ws.runtime.exceptions.UnauthorizedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class TFSClientImpl extends SpringBeanAutowiringSupport implements TFSClient {

    @Autowired(required = false)
    private ProxyService proxyService;

    protected static final SanitizedLogger LOG = new SanitizedLogger("TFSClientImpl");

    // We need to load the native libraries and this seems to be the best spot.
    // The idea is to use the same code for loading all the libraries but use
    // string values to specify which folder they are in and which names to look up.
    static {
        String osName = System.getProperty("os.name"), osArch = System.getProperty("os.arch");
        LOG.info("Attempting to load libraries for " + osName + ".");

        String folderName = null, prefix = null, suffix = null;
        String[] names = null;

        if (osName == null) {
            LOG.error("Received null from System.getProperty(\"os.name\"), " +
                    "something is wrong here.");
        } else if (osName.startsWith("Windows")) {
            folderName = "/tfs-native/win32/x86";
            if (osArch != null && osArch.contains("64")) {
                folderName += "_64";
            }
            prefix = "native_";
            suffix = ".dll";
            names = new String[] { "synchronization", "auth", "console",
                    "filesystem", "messagewindow", "misc", "registry" };

        } else if (osName.startsWith("Mac OS")) {
            folderName = "/tfs-native/macosx";
            prefix = "libnative_";
            suffix = ".jnilib";
            names = new String[] { "auth", "console", "filesystem", "keychain",
                    "misc", "synchronization" };
        } else if (osName.startsWith("Linux")) {
            String archExtension = osArch;
            if (osArch.equals("amd64")) {
                archExtension = "x86_64";
            } else if (osArch.equals("i386")) {
                archExtension = "x86";
            }

            folderName = "/tfs-native/linux/" + archExtension;
            prefix = "libnative_";
            suffix = ".so";
            names = new String[] { "auth", "console", "filesystem", "misc",
                    "synchronization" };

        } else if (osName.equals("hpux") || osName.equals("aix")
                || osName.equals("solaris")) {
            folderName = "/tfs-native/" + osName + "/";
            prefix = "libnative_";
            suffix = ".so";
            if (osArch != null && osArch.equals("PA_RISC")) {
                suffix = ".sl";
            } else if (osArch != null && osArch.equals("ppc")) {
                suffix = ".a";
            }
        } else {
            LOG.error("OS name not supported by TFS. " +
                    "The TFS integration will fail.");
        }

        if (folderName != null && names != null) {
            try {

                URL url = ResourceUtils.getResourceAsUrl(folderName);

                if (url != null) {
                    String base = url.toURI().getPath()
                            .replaceFirst("file:", "");
                    try {
                        for (String library : names) {
                            System.load(base + prefix + library + suffix);
                        }

                        LOG.info("Successfully loaded native libraries for "
                                + osName + ".");
                    } catch (UnsatisfiedLinkError e) {
                        LOG.error("Unable to locate one of the libraries.", e);
                    }
                }
            } catch (URISyntaxException e) {
                LOG.error("Unable to convert the path String to a URI.", e);
            }

        } else {
            LOG.error("Attempt to load TFS native libraries failed..");
        }
    }

    ConnectionStatus lastStatus = ConnectionStatus.INVALID;
    WorkItemClient client = null;

    @Override
    public void updateDefectIdMaps(String ids, Map<String, String> stringStatusMap, Map<String, Boolean> openStatusMap) {
        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to submit a defect.");
            return;
        }

        String wiqlQuery = "Select ID, State from WorkItems where (id in ("
                + ids + "))";

        // Run the query and get the results.
        WorkItemCollection workItems = client.query(wiqlQuery);

        for (int i = 0; i < workItems.size(); i++) {
            WorkItem workItem = workItems.getWorkItem(i);

            stringStatusMap.put(String.valueOf(workItem.getID()),
                    (String) workItem.getFields().getField("State")
                            .getOriginalValue());
            openStatusMap.put(String.valueOf(workItem.getID()),
                    workItem.isOpen());
        }

        client.close();
    }

    @Override
    public List<String> getPriorities() {
        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to submit a defect.");
            return null;
        }

        List<String> returnPriorities = list();

        FieldDefinitionCollection collection = client
                .getFieldDefinitions();

        Collections.addAll(returnPriorities, collection.get("Priority")
                .getAllowedValues().getValues());

        client.close();

        return returnPriorities;
    }

    @Override
    public List<String> getDefectIds(String projectName) {
        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to get defect IDs.");
            return null;
        }

        String wiqlQuery = "Select [System.Id] from WorkItems Where [System.TeamProject] = '" + projectName + "'";

        // Run the query and get the results.
        WorkItemCollection workItems = client.query(wiqlQuery);

        List<String> ids = list();

        for (int i = 0; i < workItems.size(); i++) {
            ids.add(String.valueOf(workItems.getWorkItem(i).getID()));
        }

        client.close();

        return ids;
    }

    @Override
    public List<String> getProjectNames() {
        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to submit a defect.");
            return null;
        }

        try {
            ProjectCollection collection = client.getProjects();

            List<String> strings = list();

            for (Project project : collection) {
                strings.add(project.getName());
            }

            return strings;
        } catch (UnauthorizedException | TFSUnauthorizedException e) {
            LOG.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
            return null;
        } finally {
            client.close();
        }
    }

    @Override
    public String getProjectId(String projectName) {
        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to submit a defect.");
            return null;
        }

        try {
            Project project = client.getProjects().get(projectName);

            return project == null ? null : String.valueOf(project.getID());

        } catch (UnauthorizedException | TFSUnauthorizedException e) {
            LOG.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
            return null;
        } finally {
            client.close();
        }
    }

    @Override
    public ConnectionStatus configure(String url, String username, String password) {

        try {
            Credentials credentials = new UsernamePasswordCredentials(username, password);

            URI uri = null;
            try {
                uri = new URI(url);
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }

            ConnectionAdvisor advisor = new DefaultConnectionAdvisor(Locale.getDefault(), TimeZone.getDefault());

            TFSTeamProjectCollection projects = new TFSTeamProjectCollection(uri, credentials, advisor);
            addProxy(projects.getHTTPClient());

            try {
                client = projects.getWorkItemClient();
                lastStatus = client == null ? ConnectionStatus.INVALID : ConnectionStatus.VALID;
            } catch (UnauthorizedException | TFSUnauthorizedException e) {
                LOG.warn("TFSUnauthorizedException encountered, unable to connect to TFS. " +
                        "Check credentials and endpoint.");
            }
        } catch (TECoreException e) {
            if (e.getMessage().contains("TF30059")) {
                throw new DefectTrackerUnavailableException(e,
                        "TFS is unavailable (TF30059 error). More details are available in the error logs.");
            } else {
                throw new DefectTrackerUnavailableException(e,
                        "An exception occurred while attempting to connect to TFS. " +
                                "Check the error logs for more details.");
            }
        }

        return lastStatus;
    }

    private void addProxy(com.microsoft.tfs.core.httpclient.HttpClient client) {

        if (proxyService != null && proxyService.shouldUseProxy(TFSDefectTracker.class)) {

            DefaultConfiguration config = proxyService.getDefaultConfigurationWithProxyCredentials();

            if (config.hasConfiguredHostAndPort()) {
                client.getHostConfiguration().setProxy(config.getProxyHost(), config.getProxyPort());

                if (config.hasConfiguredCredentials()) {
                    client.getState().setProxyCredentials(AuthScope.ANY,
                            new UsernamePasswordCredentials(config.getProxyUsername(), config.getProxyPassword()));
                }
            }
        }
    }

    @Override
    public String createDefect(String projectName, DefectMetadata metadata, String description) {

        if (lastStatus != ConnectionStatus.VALID || client == null) {
            LOG.error("Please configure the tracker properly before trying to submit a defect.");
            return null;
        }

        try {
            Project project = client.getProjects().get(projectName);

            if (project == null) {
                LOG.warn("Product was not found. Unable to create defect.");
                return null;
            }

            WorkItem item = client.newWorkItem(project
                    .getVisibleWorkItemTypes()[0]);

            if (item == null) {
                LOG.warn("Unable to create item in TFS.");
                return null;
            }

            item.setTitle(metadata.getDescription());
            item.getFields().getField("Description").setValue(description);
            item.getFields().getField("Priority").setValue(metadata.getPriority());

            String itemId = null;

            if (checkItemValues(item)) {
                item.save();
                itemId = String.valueOf(item.getID());
            } else {
                LOG.error("Failed to create issue because one or more fields were invalid. " +
                        "Check the above logs for more details.");
            }

            return itemId;

        } catch (UnauthorizedException | TFSUnauthorizedException e) {
            LOG.warn("Ran into TFSUnauthorizedException while trying to retrieve products.", e);
            return null;
        } finally {
            client.close();
        }
    }

    // This method checks all the item values and tries to patch them when necessary.
    private boolean checkItemValues(WorkItem item) {

        boolean valid = true;

        // we want to exit early if we find a field that we can't patch
        OUTER: for (Field field : item.getFields()) {
            if (field.getStatus() != FieldStatus.VALID) {

                if (field.getStatus() == FieldStatus.INVALID_EMPTY) {
                    LOG.info("Found INVALID_EMPTY error on field " + field.getName() +
                            ". Attempting to assign the string \"<None>\" to the field.");
                    field.setValue("<None>");
                }

                if (field.getStatus() == FieldStatus.INVALID_NOT_EMPTY) {
                    LOG.info("Found INVALID_NOT_EMPTY on field " + field.getName() + ". Setting field value to null. ");
                    field.setValue(null);
                }

                if (field.getStatus() != FieldStatus.VALID) {
                    valid = false;
                    LOG.error("Received error message for field " + field.getName() +
                            ": " + field.getStatus().getInvalidMessage(field));

                    LOG.info("Attempting to patch fields. " +
                            "This could result in different values for fields that you have set.");

                    // Read all field definitions to find the correct possible values for the field.
                    for (FieldDefinition definition : client.getFieldDefinitions()) {
                        if (definition.getName().equals(field.getName())) {
                            AllowedValuesCollection allowedValues = definition.getAllowedValues();

                            if (allowedValues.size() > 0) {

                                Object newValue = allowedValues.get(0);

                                LOG.info("List of allowed values for field " + field.getName() +
                                        " was not empty. Setting field value to the first available (" +
                                        newValue + ").");
                                field.setValue(newValue);

                                valid = field.getStatus() == FieldStatus.VALID;
                                if (field.getStatus() != FieldStatus.VALID) {
                                    LOG.error("Setting " + field.getName() + " to a known allowed value (" +
                                            newValue + ") failed. Giving up.");
                                    break OUTER;
                                } else {
                                    LOG.info("Setting " + field.getName() + " to " + newValue + " worked. Moving on.");
                                }
                            } else {
                                LOG.error("Set of possible values was empty. Giving up.");
                                valid = false;
                                break OUTER;
                            }
                        }
                    }
                }
            }
        }

        return valid;
    }

    @Override
    public ConnectionStatus checkUrl(String url) {
        Credentials credentials = new UsernamePasswordCredentials("", "");

        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            LOG.warn("Invalid syntax for the URL.",e);
            return ConnectionStatus.INVALID;
        }

        TFSTeamProjectCollection projects = new TFSTeamProjectCollection(uri,
                credentials);

        addProxy(projects.getHTTPClient());

        try {
            projects.getWorkItemClient().getProjects();
            //projects.getWorkItemClient();
            LOG.info("No UnauthorizedException was thrown when attempting to connect with blank credentials.");
            return ConnectionStatus.VALID;
        } catch (UnauthorizedException | TFSUnauthorizedException e) {
            LOG.info("Got an UnauthorizedException, which means that the TFS url was good.");
            return ConnectionStatus.VALID;
        } catch (TECoreException e) {
            if (e.getMessage().contains("unable to find valid certification path to requested target")) {
                LOG.warn("An invalid or self-signed certificate was found.");
                return ConnectionStatus.INVALID_CERTIFICATE;
            } else {
                return ConnectionStatus.INVALID;
            }
        }
    }

}
