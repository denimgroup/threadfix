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
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <tr ng-hide="scheduledEmailReports.length || loading">
                    <td colspan="6" style="text-align:center;">No email reports scheduled.</td>
                </tr>
                <tr ng-repeat-start="scheduledReport in scheduledEmailReports">
                    <td>{{ scheduledReport.scheduledDate }} {{ scheduledReport.period }}</td>
                    <td style="max-width:500px; word-wrap: break-word;"><span ng-repeat="organization in scheduledReport.organizations">{{ organization.name }} </span></td>
                    <td>{{ scheduledReport.severityLevel.displayName }}</td>
                    <td class="centered">
                        <button class="btn" ng-click="showEmailAddresses(scheduledReport)">Show/Hide</button>
                    </td>
                    <td class="centered">
                        <button class="btn" ng-click="openEditModal(scheduledReport)">Edit / Delete</button>
                    </td>
                    <td></td>
                </tr>
                <tr ng-repeat-end ng-show="scheduledReport.showEmailAddresses" class="grey-background">
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
                    <td colspan="3" style="padding:8px">
                        <table>
                            <thead ng-show="scheduledReport.emailAddresses.length > 0">
                                <tr>
                                    <th>Email Lists</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr ng-repeat="emailList in scheduledReport.emailLists">
                                    <td>{{ emailList.name }}</td>
                                    <td class="centered">
                                        <a class="btn btn-danger" ng-click="deleteEmailList(scheduledReport,emailList)">Delete</a>
                                    </td>
                                </tr>
                                <tr ng-show="scheduledReport.emailLists.length==0 && scheduledReport.showEmailAddresses">
                                    <td>No Email Lists</td>
                                </tr>
                                <tr>
                                    <td>
                                        <select ng-options="emailList.name for emailList in emailLists track by emailList.id"
                                                id="emailListSelect" ng-model="scheduledReport.newEmailList"></select>
                                    </td>
                                    <td>
                                        <a class="btn btn-primary" style="margin-top: -10px" ng-click="addNewEmailList(scheduledReport)" ng-disabled="!scheduledReport.newEmailList">Add List</a>
                                    </td>
                                    <td>
                                        <span ng-show="newEmailListLoading" class="spinner dark"></span>
                                        <span class="errors" ng-show="scheduledReport.newEmailListError"> {{ scheduledReport.newEmailListError }}</span>
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
