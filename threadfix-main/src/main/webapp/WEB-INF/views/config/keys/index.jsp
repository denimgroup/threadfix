<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>API Keys</title>
    <cbs:cachebustscript src="/scripts/api-keys-controller.js"/>
</head>

<body>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <div ng-controller="ApiKeysController">
        <h2>API Keys</h2>

        <%@ include file="/WEB-INF/views/successMessage.jspf" %>
        <%@ include file="/WEB-INF/views/errorMessage.jsp" %>
        <%@ include file="newForm.jsp" %>
        <%@ include file="editForm.jsp" %>

        <div id="helpText">
            ThreadFix API Keys are used to access the REST interface.<br/>
        </div>

        <button class="btn" ng-click="openNewModal()" id="createNewKeyModalButton">Create New Key</button>

        <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

        <table id="table" ng-hide="loading" class="table table-striped" style="table-layout:fixed;">
            <thead>
                <tr>
                    <th class="first">Key</th>
                    <th class="short">&nbsp;</th>
                    <th class="medium">Note</th>
                    <th class="centered">Edit / Delete</th>
                    <th class="short">Restricted</th>
                    <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_USERS">
                        <th class="short">User</th>
                    </security:authorize>
                </tr>
            </thead>
            <tbody>
                <tr ng-hide="keys.length || loading">
                    <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_USERS">
                        <td colspan="6" style="text-align:center;">No API Keys found.</td>
                    </security:authorize>
                    <security:authorize ifNotGranted="ROLE_CAN_MANAGE_USERS">
                        <security:authorize ifAllGranted="ROLE_ENTERPRISE">
                            <td colspan="5" style="text-align:center;">No API Keys found.</td>
                        </security:authorize>
                    </security:authorize>
                    <security:authorize ifNotGranted="ROLE_ENTERPRISE">
                        <td colspan="5" style="text-align:center;">No API Keys found.</td>
                    </security:authorize>
                </tr>
                <tr ng-repeat="key in keys">
                    <td id="key{{ key.note }}" style="vertical-align:text-top;">{{ key.apiKey }}</td>
                    <td>&nbsp;</td>
                    <td id="note{{ key.note }}" style="word-wrap:break-word;vertical-align:text-top;">{{ key.note }}</td>
                    <td class="centered" style="vertical-align: text-top;">
                        <button class="btn" id="editKeyModal{{ key.note }}" ng-click="openEditModal(key)">Edit / Delete</button>
                    </td>
                    <td id="restricted{{ key.note }}" style="vertical-align: text-top;">{{ key.isRestrictedKey }}</td>
                    <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_USERS">
                        <td id="user{{ key.note }}" style="vertical-align: text-top;">{{ key.username }}</td>
                    </security:authorize>
                </tr>
            </tbody>
        </table>

    </div>
</body>
