<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>EmailLists</title>
    <cbs:cachebustscript src="/scripts/email-lists-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body id="emailLists" ng-controller="EmailListsPageController">

    <h2>Email Lists</h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf" %>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/config/emailLists/createEmailListForm.jsp" %>
    <%@ include file="/WEB-INF/views/config/emailLists/editEmailListForm.jsp" %>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a ng-show="initialized" id="createEmailListModalButton" ng-click="openNewModal()" class="btn">Create Email List</a>

    <table ng-show="initialized" class="table table-striped">
        <thead>
            <tr>
                <th class="long first">Name</th>
                <th class="centered">Edit / Delete</th>
                <th class="centered">Show / Hide Email Addresses</th>
            </tr>
        </thead>
        <tbody id="emailListTableBody">
            <tr ng-hide="emailLists" class="bodyRow">
                <td colspan="4" style="text-align:center;">No email lists found.</td>
            </tr>
            <tr ng-repeat-start="emailList in emailLists" ng-show="emailLists" class="bodyRow">
                <td class="details pointer" id="emailListName{{ emailList.name }}">
                    {{ emailList.name }}
                </td>
                <td class="centered">
                    <a id="editEmailListModalButton{{ emailList.name }}" ng-click="openEditModal(emailList)" class="btn">Edit / Delete</a>
                </td>
                <td class="centered">
                    <button class="btn" ng-click="showEmailAddresses(emailList)">Show/Hide</button>
                </td>
            </tr>
            <tr ng-repeat-end ng-show="emailList.showEmailAddresses" class="grey-background">
                <td colspan="3">
                    <table>
                        <thead ng-show="emailList.emailAddresses.length > 0">
                            <tr>
                                <th>Email Address</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr ng-repeat="emailAddress in emailList.emailAddresses">
                                <td>{{ emailAddress }}</td>
                                <td class="centered">
                                    <a class="btn btn-danger" ng-click="deleteEmailAddress(emailList,emailAddress)">Delete</a>
                                </td>
                            </tr>
                            <tr ng-show="emailList.emailAddresses.length==0 && emailList.showEmailAddresses">
                                <td>No Email Addresses</td>
                            </tr>
                            <tr>
                                <td>
                                    <input type="email" style="margin: auto" ng-model="emailList.newEmailAddress"/>
                                </td>
                                <td>
                                    <a class="btn btn-primary" ng-click="addNewEmail(emailList)" ng-disabled="!emailList.newEmailAddress">Add Email</a>
                                </td>
                                <td>
                                    <span ng-show="newEmailLoading" class="spinner dark"></span>
                                    <span class="errors" ng-show="emailList.newEmailError"> {{ emailList.newEmailError }}</span>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </td>
            </tr>
        </tbody>
    </table>
</body>
