<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Scheduled Email Reports</title>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/scheduled-email-reports-controller.js"/>
</head>

<body>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <div ng-controller="ScheduledEmailReportsController">
        <h2>Scheduled Email Reports</h2>

        <%@ include file="/WEB-INF/views/successMessage.jspf" %>
        <%@ include file="/WEB-INF/views/errorMessage.jsp" %>
        <%@ include file="modals/createScheduledReportModal.jsp" %>
        <%@ include file="modals/editScheduledReportModal.jsp" %>

        <button class="btn" ng-click="openNewModal()">New Schedule Email Report</button>
        <span class="errors" ng-hide="isConfiguredEmail">Your email.properties file is not configured, the emails won't be sent.</span>

        <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

        <table id="table" ng-hide="loading" class="table" style="table-layout:fixed;">
            <thead>
                <tr>
                    <th>Scheduled Time</th>
                    <th>Teams</th>
                    <th>Severity Threshold</th>
                    <th class="centered">Email addresses</th>
                    <th class="centered">Edit / Delete</th>
                </tr>
            </thead>
            <tbody>
                <tr ng-hide="scheduledEmailReports.length || loading">
                    <td colspan="4" style="text-align:center;">No email reports scheduled.</td>
                </tr>
                <tr ng-repeat-start="scheduledReport in scheduledEmailReports">
                    <td>{{ scheduledReport.scheduledDate }} {{ scheduledReport.period }}</td>
                    <td style="max-width:500px; word-wrap: break-word;"><span ng-repeat="organization in scheduledReport.organizations">{{ organization.name }} </span></td>
                    <td>{{ scheduledReport.severityLevel.name }}</td>
                    <td class="centered">
                        <button class="btn" ng-click="showEmailAddresses(scheduledReport)">Show/Hide</button>
                    </td>
                    <td class="centered">
                        <button class="btn" ng-click="openEditModal(scheduledReport)">Edit / Delete</button>
                    </td>
                </tr>
                <tr ng-repeat-end ng-show="scheduledReport.showEmailAddresses"
                    class="grey-background">
                    <td colspan="3">
                        <table>
                            <thead ng-show="scheduledReport.emailAddresses.length > 0">
                                <tr>
                                    <th>Email Address</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr ng-repeat="emailAddress in scheduledReport.emailAddresses">
                                    <td>{{ emailAddress }}</td>
                                    </td>
                                    <td class="centered">
                                      <a class="btn btn-danger" ng-click="deleteEmailAddress(scheduledReport,emailAddress)">Delete</a>
                                    </td>
                                </tr>
                                <tr ng-show="scheduledReport.emailAddresses.length==0 && scheduledReport.showEmailAddresses">
                                    <td>No Email Addresses</td>
                                </tr>
                                <tr>
                                    <td>
                                         <input type="email" style="margin: auto" ng-model="scheduledReport.newEmailAddress"/>
                                    </td>
                                    <td>
                                         <a class="btn btn-primary" ng-click="addNewEmail(scheduledReport)" ng-disabled="!scheduledReport.newEmailAddress">Add Email</a>
                                    </td>
                                    <td>
                                         <span ng-show="newEmailLoading" class="spinner dark"></span>
                                         <span class="errors" ng-show="scheduledReport.newEmailError"> {{ scheduledReport.newEmailError }}</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </td>
                </tr>
            </tbody>
        </table>

    </div>
</body>
