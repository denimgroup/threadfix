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
package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name = "Event")
public class Event extends AuditableEntity {

    private static final long serialVersionUID = 1L;

    public static final int
            ENUM_LENGTH = 50,
            STATUS_LENGTH = 255;

    private Date date = new Date();

    String eventAction = null;

    Boolean apiAction = false;

    private Application application;
    private User user;
    private Vulnerability vulnerability;
    private Scan scan;
    private Integer deletedScanId;
    private Defect defect;
    private VulnerabilityComment comment;
    private String detail;
    private String status;

    private Long groupCount;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(nullable = false)
    @JsonView({ AllViews.HistoryView.class})
    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    @Column(length = ENUM_LENGTH)
    @JsonView({ AllViews.HistoryView.class})
    public String getEventAction() {
        return eventAction;
    }

    public void setEventAction(String eventAction) {
        this.eventAction = eventAction;
    }

    @Transient
    @JsonIgnore
     public EventAction getEventActionEnum() {
        return EventAction.getEventAction(eventAction);
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public String getEventActionDisplayName() {
        EventAction eventAction = getEventActionEnum();
        if (eventAction != null) {
            return eventAction.getDisplayName();
        } else {
            return null;
        }
    }

    @Column
    public Boolean isApiAction() {
        return apiAction != null && apiAction;
    }

    public void setApiAction(Boolean apiAction) {
        this.apiAction = apiAction;
    }

    @ManyToOne
    @JoinColumn(name = "applicationId")
    @JsonIgnore
    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Integer getApplicationId() {
        Application application = getApplication();
        if (application != null) {
            return application.getId();
        }
        return null;
    }

    @ManyToOne
    @JoinColumn(name = "userId")
    @JsonIgnore
    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public String getUserName() {
        User user = getUser();
        String userName = null;
        if (user != null) {
            userName = user.getDisplayName();
        }
        if (userName != null) {
            return userName;
        } else {
            return "Threadfix";
        }
    }

    @ManyToOne
    @JoinColumn(name = "vulnerabilityId")
    @JsonIgnore
    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Integer getVulnerabilityId() {
        Vulnerability vulnerability = getVulnerability();
        if (vulnerability != null) {
            return vulnerability.getId();
        }
        return null;
    }

    @ManyToOne
    @JoinColumn(name = "scanId")
    @JsonIgnore
    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Integer getScanId() {
        Scan scan = getScan();
        if (scan != null) {
            return scan.getId();
        }
        return null;
    }

    @JoinColumn(name = "deletedScanId")
    @JsonIgnore
    public Integer getDeletedScanId() {
        return deletedScanId;
    }

    public void setDeletedScanId(Integer deletedScanId) {
        this.deletedScanId = deletedScanId;
    }

    @ManyToOne
    @JoinColumn(name = "defectId")
    @JsonIgnore
    public Defect getDefect() {
        return defect;
    }

    public void setDefect(Defect defect) {
        this.defect = defect;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Integer getDefectId() {
        Defect defect = getDefect();
        if (defect != null) {
            return defect.getId();
        }
        return null;
    }

    @ManyToOne
    @JoinColumn(name = "commentId")
    @JsonIgnore
    public VulnerabilityComment getVulnerabilityComment() {
        return comment;
    }

    public void setVulnerabilityComment(VulnerabilityComment comment) {
        this.comment = comment;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Integer getVulnerabilityCommentId() {
        VulnerabilityComment comment = getVulnerabilityComment();
        if (comment != null) {
            return comment.getId();
        }
        return null;
    }

    @Column(length = STATUS_LENGTH)
    @JsonView({ AllViews.HistoryView.class})
    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    @Column(length = STATUS_LENGTH)
    @JsonView({ AllViews.HistoryView.class})
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public Long getGroupCount() {
        return groupCount;
    }

    public void setGroupCount(Object groupCount) {
        try {
            this.groupCount = (Long) groupCount;
        } catch (Exception e) {
            this.groupCount = -11l;
        }
    }

    @Transient
    @JsonView({ AllViews.HistoryView.class})
    public String getDescription() {
        String description = null;
        switch (getEventActionEnum()) {
            default:
                description = getUserName() + " performed an action: " + getEventActionDisplayName();
        }
        return description;
    }

    @Transient
    @JsonView({ AllViews.OrganizationHistoryView.class})
    public Map<String, Object> getTeamDescriptionWithUrls() {
        return getFormattedDescriptionWithUrls(HistoryView.ORGANIZATION_HISTORY);
    }

    @Transient
    @JsonView({ AllViews.ApplicationHistoryView.class})
    public Map<String, Object> getApplicationDescriptionWithUrls() {
        return getFormattedDescriptionWithUrls(HistoryView.APPLICATION_HISTORY);
    }

    @Transient
    @JsonView({ AllViews.VulnerabilityHistoryView.class})
    public Map<String, Object> getVulnerabilityDescriptionWithUrls() {
        return getFormattedDescriptionWithUrls(HistoryView.VULNERABILITY_HISTORY);
    }

    @Transient
    @JsonView({ AllViews.UserHistoryView.class})
    public Map<String, Object> getUserDescriptionWithUrls() {
        return getFormattedDescriptionWithUrls(HistoryView.USER_HISTORY);
    }

    @Transient
    @JsonIgnore
    private Map<String, Object> getFormattedDescriptionWithUrls(HistoryView historyView) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("MMMM d, yyyy h:mm:ss a");

        Map<String, Object> descriptionUrlMap = new HashMap<String, Object>();
        descriptionUrlMap.put("urlCount", 0);

        StringBuilder description = new StringBuilder();
        switch (getEventActionEnum()) {
            case APPLICATION_CREATE:
                description.append(getUserName()).append(" created Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case APPLICATION_EDIT:
                description.append(getUserName()).append(" edited Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case APPLICATION_SET_TAGS:
                description.append(getUserName()).append(" set tags on Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case APPLICATION_SCAN_UPLOADED:
                description.append(getUserName()).append(" uploaded a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case APPLICATION_SCAN_DELETED:
                description.append(getUserName()).append(" deleted a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" for Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_CREATE:
                description.append(getUserName()).append(" created Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_OPEN_SCAN_UPLOAD:
                description.append(getUserName()).append(" created Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_OPEN_SCAN_DELETED:
                description.append(getUserName()).append(" opened Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" deleting a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" for Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case GROUPED_VULNERABILITY_OPEN_SCAN_UPLOAD:
                description.append(getUserName()).append(" created ").append(getGroupCount()).append(" Vulnerabilities");
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case GROUPED_VULNERABILITY_OPEN_SCAN_DELETED:
                description.append(getUserName()).append(" opened ").append(getGroupCount()).append(" Vulnerabilities");
                description.append(" deleting a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" for Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_CLOSE:
                description.append(getUserName()).append(" closed Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_CLOSE_FINDINGS_MERGE:
                description.append(getUserName()).append(" closed Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" merging findings");
                description.append(".");
                break;
            case VULNERABILITY_CLOSE_SCAN_UPLOAD:
                description.append(getUserName()).append(" closed Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_CLOSE_SCAN_DELETED:
                description.append(getUserName()).append(" closed Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" deleting a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" for Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_CLOSE_MANUAL:
                description.append(getUserName()).append(" closed Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case GROUPED_VULNERABILITY_CLOSE_SCAN_UPLOAD:
                description.append(getUserName()).append(" closed ").append(getGroupCount()).append(" Vulnerabilities");
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case GROUPED_VULNERABILITY_CLOSE_SCAN_DELETED:
                description.append(getUserName()).append(" closed ").append(getGroupCount()).append(" Vulnerabilities");
                description.append(" deleting a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" for Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_REOPEN:
                description.append(getUserName()).append(" reopened Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_REOPEN_SCAN_UPLOAD:
                description.append(getUserName()).append(" reopened Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_REOPEN_MANUAL:
                description.append(getUserName()).append(" reopened Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case GROUPED_VULNERABILITY_REOPEN_SCAN_UPLOAD:
                description.append(getUserName()).append(" reopened ").append(getGroupCount()).append(" Vulnerabilities");
                description.append(" uploading a ")
                        .append(buildScanLink(getScan(), "Scan", descriptionUrlMap))
                        .append(" to Application");
                appendApplicationLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_MARK_FALSE_POSITIVE:
                description.append(getUserName()).append(" marked Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" as false positive");
                description.append(".");
                break;
            case VULNERABILITY_UNMARK_FALSE_POSITIVE:
                description.append(getUserName()).append(" unmarked Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" as false positive");
                description.append(".");
                break;
            case VULNERABILITY_COMMENT:
                description.append(getUserName()).append(" commented on Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case VULNERABILITY_OTHER:
                description.append(getUserName()).append(" performed an action on Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case DEFECT_SUBMIT:
                description.append(getUserName()).append(" submitted Defect ");
                appendDefectLing(description, descriptionUrlMap, historyView);
                description.append(" for Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case DEFECT_STATUS_UPDATED:
                description.append(getUserName()).append(" updated the status of Defect ");
                appendDefectLing(description, descriptionUrlMap, historyView);
                description.append(" for Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case DEFECT_CLOSED:
                description.append(getUserName()).append(" closed Defect ");
                appendDefectLing(description, descriptionUrlMap, historyView);
                description.append(" for Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            case DEFECT_APPEARED_AFTER_CLOSED:
                // TODO: this needs to be reworded!!!
                description.append(getUserName()).append(" uploaded a Scan with Vulnerability");
                appendVulnerabilityLink(description, descriptionUrlMap, historyView);
                description.append(" with previously closed Defect ");
                appendDefectLing(description, descriptionUrlMap, historyView);
                description.append(".");
                break;
            default:
                description.append(getUserName()).append(" performed an action").append(getEventActionDisplayName());
                if (getGroupCount() != null) {
                    description.append(" on ").append(getGroupCount()).append(" items");
                }
                description.append(": ");
                description.append(".");
        }

        String detail = getDetail();
        if (detail != null) {
            description.append(" <span class='detail'>").append(detail).append("</span>");
        }

        descriptionUrlMap.put("string", description.toString());

        return descriptionUrlMap;
    }

    private void appendApplicationLink(StringBuilder description, Map<String, Object> descriptionUrlMap, HistoryView historyView) {
        if ((getApplication() != null) && (historyView != HistoryView.APPLICATION_HISTORY) && (historyView != HistoryView.VULNERABILITY_HISTORY)) {
            description.append(" ").append(buildApplicationLink(getApplication(), getApplication().getName(), descriptionUrlMap));
        }
    }

    private String buildApplicationLink(Application application, String linkText, Map<String, Object> urlMap) {
        if (application == null) {
            return linkText;
        }
        String urlString = "/organizations/" +
                application.getOrganization().getId() +
                "/applications/" +
                application.getId();
        return buildLink(urlString, linkText, urlMap);
    }

    private String buildScanLink(Scan scan, String linkText, Map<String, Object> urlMap) {
        if (scan == null) {
            return linkText;
        }
        String urlString = "/organizations/" +
                scan.getApplication().getOrganization().getId() +
                "/applications/" +
                scan.getApplication().getId() +
                "/scans/" +
                scan.getId();
        return buildLink(urlString, linkText, urlMap);
    }

    private void appendVulnerabilityLink(StringBuilder description, Map<String, Object> descriptionUrlMap, HistoryView historyView) {
        if ((getVulnerability() != null) && (historyView != HistoryView.VULNERABILITY_HISTORY)) {
            description.append(" ").append(buildVulnerabilityLink(getVulnerability(), getVulnerability().getVulnerabilityName(), descriptionUrlMap));
        }
    }

    private String buildVulnerabilityLink(Vulnerability vulnerability, String linkText, Map<String, Object> urlMap) {
//        if (vulnerability == null) {
            return linkText;
//        }
//        String urlString = "/organizations/" +
//                vulnerability.getApplication().getOrganization().getId() +
//                "/applications/" +
//                vulnerability.getApplication().getId() +
//                "/vulnerabilities/" +
//                vulnerability.getId();
//        return buildLink(urlString, linkText, urlMap);
    }

    private void appendDefectLing(StringBuilder description, Map<String, Object> descriptionUrlMap, HistoryView historyView) {
        if (getDefect() != null) {
            description.append(buildDefectLink(getVulnerability(), getDefect().getNativeId(), descriptionUrlMap));
        }
    }

    private String buildDefectLink(Vulnerability vulnerability, String linkText, Map<String, Object> urlMap) {
        if (defect == null || vulnerability == null) {
            return linkText;
        }
        String urlString = "/organizations/" +
                vulnerability.getApplication().getOrganization().getId() +
                "/applications/" +
                vulnerability.getApplication().getId() +
                "/vulnerabilities/" +
                vulnerability.getId() +
                "/defect";
        return buildLink(urlString, linkText, urlMap);
    }

    private String buildLink(String urlString, String linkText, Map<String, Object> urlMap) {
        String urlIdentifier = addUrl(urlMap, urlString);
        String link = "<a href='" + urlIdentifier + "'>" + linkText + "</a>";
        return link;
    }

    private String addUrl(Map<String, Object> urlMap, String urlString) {
        int urlCount = (Integer)urlMap.get("urlCount");
        String urlIdentifier = "{URL_" + urlCount + "}";
        urlMap.put(urlIdentifier, urlString);
        urlMap.put("urlCount", ++urlCount);
        return urlIdentifier;
    }

    private enum HistoryView {
        ORGANIZATION_HISTORY, APPLICATION_HISTORY, VULNERABILITY_HISTORY, USER_HISTORY;
    }
}
