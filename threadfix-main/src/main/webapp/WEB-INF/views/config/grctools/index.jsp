<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>GRC Tools</title>
    <cbs:cachebustscript src="/scripts/grc-tools-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body id="config" ng-controller="GRCToolsController">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="modals/createGRCTool.jsp" %>
    <%@ include file="modals/editGRCTool.jsp" %>

    <h2>GRC Tools</h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf"%>

    <button class="btn" id="addNewGRCToolButton" ng-click="openNewModal()">Create GRC Tool</button>

    <div ng-show="loading" style="float:right" class="modal-loading">
        <div><span class="spinner dark"></span>Loading...</div>
    </div>

    <table id="grcToolsTableBody" ng-hide="loading" class="table table-striped">
        <thead>
            <tr>
                <th class="medium first">Name</th>
                <th class="long">URL</th>
                <th>Type</th>
                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_GRC_TOOLS">
                    <th></th>
                    <th class="centered">Edit / Delete</th>
                </security:authorize>
            </tr>
        </thead>
        <tbody>
            <tr ng-show="empty">
                <td colspan="5" style="text-align:center;">No GRC Tools found.</td>
            </tr>
            <tr ng-repeat="grcTool in grcTools">
                <td id="grcToolName{{ grcTool.name }}">
                    {{ grcTool.name }}
                </td>
                <td id="grcToolUrl{{ grcTool.name }}">
                    {{ grcTool.url }}
                </td>
                <td id="grcToolType{{ grcTool.name }}">
                    {{ grcTool.grcToolType.name }}
                </td>
                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_GRC_TOOLS">
                    <td class="centered">
                        <a id="updateGRCAppsButton{{ grcTool.name }}" class="btn btn-primary" ng-click="updateGRCApps(grcTool)">Get Apps</a>
                    </td>
                    <td class="centered">
                        <a id="editGRCToolButton{{ grcTool.name }}" class="btn" ng-click="openEditModal(grcTool)">Edit / Delete</a>
                    </td>
                </security:authorize>
            </tr>
        </tbody>
    </table>

    <div ng-show="grcApplications">

        <div ng-show="grcApplications" class="pagination" ng-init="provider.page = 1">
            <pagination class="no-margin"
                        total-items="grcApplications.length / 100"
                        max-size="5"
                        page="provider.page"
                        ng-click="paginate(provider)"></pagination>
        </div>

        <table ng-show="grcApplications" class="table table-striped" style="table-layout:fixed;">
            <thead>
                <tr>
                    <th class="medium first">Name</th>
                    <th class="medium">Policy Number</th>
                    <th class="medium">Application</th>
                    <th class="medium"></th>
                </tr>
            </thead>
            <tbody>
                <tr ng-repeat="app in grcApplications">
                    <td id="appid{{ app.id }}">
                        {{ app.name }}
                    </td>
                    <td id="grcPolicyNumber{{ app.id }}">
                        {{ app.policyNumber }}
                    </td>
                    <td id="appPolicyNumber{{ app.id }}">
                        <div ng-show="app.application" style="word-wrap: break-word;max-width:170px;text-align:left;">
                            <a class="pointer" ng-click="goToTeam(app.application.team)">
                                {{ app.application.team.name }}
                            </a>
                        </div>
                    </td>
                    <td class="centered">
                        <a id="grcLinkApp{{ app.id }}" class="btn" ng-click="openLinkGRCModal()">Link App</a>
                    </td>
                </tr>
            </tbody>
            <tfoot>
                <tr class="footer">
                    <td colspan="12" class="pagination" style="text-align:right"></td>
                </tr>
            </tfoot>
        </table>
    </div>
</body>