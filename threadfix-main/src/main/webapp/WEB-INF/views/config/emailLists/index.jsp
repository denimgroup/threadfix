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

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a ng-show="initialized" id="createEmailListModalButton" ng-click="openNewModal()" class="btn">Create Email List</a>

    <table ng-show="initialized" class="table table-striped">
        <thead>
            <tr>
                <th class="long first">Name</th>
                <th class="centered">Edit / Delete</th>
            </tr>
        </thead>
        <tbody id="emailListTableBody">
            <tr ng-hide="emailLists" class="bodyRow">
                <td colspan="4" style="text-align:center;">No email lists found.</td>
            </tr>
            <tr ng-show="emailLists" ng-repeat="emailList in emailLists" class="bodyRow">
                <td class="details pointer" id="emailListName{{ emailList.name }}">
                    {{ emailList.name }}
                </td>
            </tr>
        </tbody>
    </table>
</body>
