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
package com.denimgroup.threadfix.importer.impl.remoteprovider.realtimeprovider;

import com.denimgroup.threadfix.data.entities.RealtimeMetaDataScan;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.RemoteProvider;
import com.denimgroup.threadfix.importer.impl.remoteprovider.realtimeprovider.utils.FortifySscClient;
import com.fortify.schema.fws.*;
import com.fortify.schema.issuemanagement.AuditView;
import com.fortify.schema.issuemanagement.FilterSetDescription;
import com.fortify.schema.issuemanagement.GroupingValue;
import com.fortify.schema.issuemanagement.IssueListDescription;
import com.fortifysoftware.schema.wsTypes.Project;
import com.fortifysoftware.schema.wsTypes.ProjectVersionLite;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import javax.xml.soap.SOAPMessage;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class RealtimeFortifyClient extends RemoteProvider {

    private String folderIdHigh;
    private String folderIdCritical;
    private String filterIdFilterOne;
    private String filterIdFilterTwo;
    private Multimap<String, String> filterIdFolderIdMap = ArrayListMultimap.create();

    public RealtimeFortifyClient() {
        super(ScannerType.FORTIFY_SSC_REALTIME);
    }

    /**
     * Returns a map of project version ID and the project name
     * */
    public final Map<Long, String> getApplication() {
        try {
            Multimap<Long, ProjectVersionLite> projectLookupMap = ArrayListMultimap.create();
            Map<Long, String> multimap = new HashMap<>();

            URL url = new URL(remoteProviderType.getUrl());

            FortifySscClient client = new FortifySscClient(url, remoteProviderType.getUsername(), remoteProviderType.getPassword());

            ActiveProjectVersionListRequestDocument activeProjectsReqDoc = ActiveProjectVersionListRequestDocument.Factory.newInstance();
            activeProjectsReqDoc.addNewActiveProjectVersionListRequest();


            SOAPMessage soapRequest1 = client.createSoapMessage(activeProjectsReqDoc);
            SOAPMessage soapResponse1 = client.callEndpoint(soapRequest1);

            ActiveProjectVersionListResponseDocument activeProjectsRespDoc = client.parseMessage(soapResponse1, ActiveProjectVersionListResponseDocument.class);

            List<ProjectVersionLite> activeProjectList = Arrays.asList(activeProjectsRespDoc.getActiveProjectVersionListResponse().getProjectVersionArray());
            for (ProjectVersionLite project : activeProjectList) {
                projectLookupMap.put(project.getProjectId(), project);
            }

            ProjectListRequestDocument reqDoc = ProjectListRequestDocument.Factory.newInstance();
            reqDoc.addNewProjectListRequest();


            SOAPMessage soapRequest = client.createSoapMessage(reqDoc);
            SOAPMessage soapResponse = client.callEndpoint(soapRequest);
            ProjectListResponseDocument respDoc = client.parseMessage(soapResponse, ProjectListResponseDocument.class);
            List<Project> projectList = Arrays.asList(respDoc.getProjectListResponse().getProjectArray());

            for (Project project : projectList) {

                Collection<ProjectVersionLite> projectVersions = projectLookupMap.get(project.getId());
                for (ProjectVersionLite projectVersion : projectVersions) {
                    multimap.put(projectVersion.getId(), project.getName() + projectVersion.getName());
                }
            }
            return multimap;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Calls the getScans method and return a list of Scans
     */
    @Override
    public final List<Scan> getScans(final RemoteProviderApplication remoteProviderApplication) {
        try {

            URL url = new URL(remoteProviderApplication.getRemoteProviderType().getUrl());
            FortifySscClient client =
                    new FortifySscClient(url, remoteProviderApplication.getRemoteProviderType().getUsername(),
                            remoteProviderApplication.getRemoteProviderType().getPassword());

            initializeFolderandFilters(remoteProviderApplication, client);

            RealtimeMetaDataScan scan = new RealtimeMetaDataScan();
            scan.setRemoteProviderApplication(remoteProviderApplication);
            scan.setImportTime(Calendar.getInstance());
            scan.setApplication(remoteProviderApplication.getApplication());
            scan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());

            for (String filterid : filterIdFolderIdMap.keys()) {
                for (String folderid : filterIdFolderIdMap.get(filterid)) {
                    GroupingValuesRequestDocument valuesRequestDocument =
                            GroupingValuesRequestDocument.Factory.newInstance();
                    GroupingValuesRequestDocument.GroupingValuesRequest groupingValuesRequest =
                            valuesRequestDocument.addNewGroupingValuesRequest();
                    groupingValuesRequest.addNewProjectIdentifier().setProjectVersionId(Long.parseLong(
                            remoteProviderApplication.getNativeId()));

                    IssueListDescription id1 = groupingValuesRequest.addNewIssueListDescription();
                    id1.setFilterSetId(filterid);
                    id1.setFolderId(folderid);

                    SOAPMessage soapRequest1 = client.createSoapMessage(valuesRequestDocument);
                    SOAPMessage soapResponse1 = client.callEndpoint(soapRequest1);

                    GroupingValuesResponseDocument gvd = client.parseMessage(soapResponse1,
                            GroupingValuesResponseDocument.class);
                    GroupingValuesResponseDocument.GroupingValuesResponse gvrd = gvd.getGroupingValuesResponse();

                    List<GroupingValue> gv = Arrays.asList(gvrd.getGroupingValuesArray());

                    Integer auditSum = 0;
                    Integer vulnSum = 0;
                    for (GroupingValue aGv : gv) {
                        auditSum += aGv.getAuditedCount();
                        vulnSum += aGv.getTotalCount();
                    }

                    if (filterid.equals(filterIdFilterOne)) {
                        if (folderid.equals(folderIdCritical)) {
                            scan.setNumberRealtimeCriticalAuditedVulnerabilities(auditSum);
                            scan.setNumberRealtimeCriticalVulnerabilities(vulnSum);

                        }
                        if (folderid.equals(folderIdHigh)) {
                            scan.setNumberRealtimeHighAuditedVulnerabilities(auditSum);
                            scan.setNumberRealtimeHighVulnerabilities(vulnSum);
                        }
                    } else if (filterid.equals(filterIdFilterTwo)) {
                        if (folderid.equals(folderIdCritical)) {
                            scan.setNumberCriticalVulnerabilities(vulnSum.longValue());
                            scan.setNumberTotalAuditedVulnerabilities(scan.getNumberTotalAuditedVulnerabilities() + auditSum);


                        }
                        if (folderid.equals(folderIdHigh)) {
                            scan.setNumberHighVulnerabilities(vulnSum.longValue());
                            scan.setNumberTotalAuditedVulnerabilities(scan.getNumberTotalAuditedVulnerabilities() + auditSum);
                        }
                    }
                }
                if (filterid.equals(filterIdFilterTwo)) {
                    scan.setNumberTotalVulnerabilities(scan.getNumberHighVulnerabilities().intValue() +
                            scan.getNumberCriticalVulnerabilities().intValue());
                }
            }

            List<Scan> scan1 = new ArrayList<>();
            scan1.add(scan);
            return scan1;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /*
    * Calls the getApplications method which connects to fortify and returns map of prduct name
    * and product versions. This method returns a list of RemoteProviderApplication
    * */
    @Override
    public final List<RemoteProviderApplication> fetchApplications() {
        try {
            Map<Long, String> multimap = getApplication();
            List<RemoteProviderApplication> list = new ArrayList<>();
            RemoteProviderApplication application;

            for (Long id : multimap.keySet()) {
                application = new RemoteProviderApplication();
                application.setNativeId(id.toString());
                application.setNativeName(multimap.get(id));

                list.add(application);
            }
            return list;
        } catch (Exception ignored) {

        }
        return null;
    }


    public final void initializeFolderandFilters(final RemoteProviderApplication remoteProviderApplication,
                                                 final FortifySscClient client) throws Exception {
        Resource resource = new ClassPathResource("/FortifySSC.properties");
        Properties props = PropertiesLoaderUtils.loadProperties(resource);


        AuditViewRequestDocument auditViewRequestDocument = AuditViewRequestDocument.Factory.newInstance();
        AuditViewRequestDocument.AuditViewRequest auditViewRequest = auditViewRequestDocument.addNewAuditViewRequest();
        auditViewRequest.setProjectVersionId(Long.parseLong(remoteProviderApplication.getNativeId()));

        SOAPMessage soapRequest1 = client.createSoapMessage(auditViewRequestDocument);
        SOAPMessage soapResponse1 = client.callEndpoint(soapRequest1);

        AuditViewResponseDocument auditViewResponse = client.parseMessage(soapResponse1, AuditViewResponseDocument.class);
        AuditViewResponseDocument.AuditViewResponse avr = auditViewResponse.getAuditViewResponse();

        AuditView auditView = avr.getAuditView();
        for (FilterSetDescription fd : Arrays.asList(auditView.getFilterSetsArray())) {

            if (fd.getName().equals(props.getProperty("Filter1"))) {
                filterIdFilterOne = fd.getFilterSetId();
            }
            if (fd.getName().equals(props.getProperty("Filter2"))) {
                filterIdFilterTwo = fd.getFilterSetId();
            }
        }

        String high = auditView.getEnabledFolders();
        String regex= props.getProperty("Folder1")+ "(.{36})";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(high);

        while (matcher.find()) {
            folderIdHigh = matcher.group().substring(props.getProperty("Folder1").length());
        }
        String critical = auditView.getEnabledFolders();
        regex= props.getProperty("Folder2")+ "(.{36})";
        pattern = Pattern.compile(regex);
        matcher = pattern.matcher(critical);

        while (matcher.find()) {
            folderIdCritical = matcher.group().substring(props.getProperty("Folder2").length());
        }

        filterIdFolderIdMap.put(filterIdFilterOne, folderIdCritical);
        filterIdFolderIdMap.put(filterIdFilterOne, folderIdHigh);
        filterIdFolderIdMap.put(filterIdFilterTwo, folderIdCritical);
        filterIdFolderIdMap.put(filterIdFilterTwo, folderIdHigh);
    }
}
