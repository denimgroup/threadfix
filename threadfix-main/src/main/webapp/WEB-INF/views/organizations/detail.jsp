<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ organization.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/team-detail-page-controller.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/reports-controller.js"></script>
</head>

<body ng-controller="TeamDetailPageController"
      id="apps">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
    <%@ include file="/WEB-INF/views/organizations/editTeamForm.jsp" %>

    <ul class="breadcrumb">
        <li><a href="<spring:url value="/organizations"/>">Applications Index</a> <span class="divider">/</span></li>
        <li class="active">Team: {{ team.name }}</li>
    </ul>
    <h2 id="name" style="padding-top:5px;">
        {{ team.name }}
        <c:if test="${ canManageTeams || canManageUsers }">
            <div id="btnDiv1" class="btn-group">
                <button id="actionButton" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
                <ul class="dropdown-menu">
                    <c:if test="${ canManageTeams }">
                        <li>
                            <a id="teamModalButton" ng-click="openEditModal()">Edit / Delete</a>
                        </li>
                    </c:if>
                    <c:if test="${ canModifyVulnerabilities }">
                        <li>
                            <spring:url value="{orgId}/filters" var="filterUrl">
                                <spring:param name="orgId" value="${ organization.id }"/>
                            </spring:url>
                            <a id="editfiltersButton1" href="<c:out value='${ filterUrl }'/>" data-toggle="modal">
                                Edit Filters
                            </a>
                        </li>
                    </c:if>
                    <c:if test="${ canManageUsers && enterprise }">
                        <li><a id="userListModelButton" href="#usersModal" data-toggle="modal">View Permissible Users</a></li>
                    </c:if>
                </ul>
            </div>
        </c:if>
    </h2>

    <div id="usersModal" class="modal hide fade" tabindex="-1"
        role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
        <div id="permissibleUsersDiv">
            <%@ include file="/WEB-INF/views/config/users/permissibleUsers.jsp" %>
        </div>
    </div>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>

    <div class="container-fluid">
        <%@ include file="/WEB-INF/views/applications/reports.jspf" %>
    </div>

    <h3 style="padding-top:5px;">Applications</h3>
    <c:if test="${ canManageApplications }">
        <div style="margin-top:10px;margin-bottom:7px;">
            <c:if test="${ canAddApps}">
                <button class="btn" id="addApplicationModalButton${ organization.id }" ng-click="openAppModal()">
                    Add Application
                </button>
            </c:if>
            <c:if test="${ not canAddApps }">
                <button class="btn" ng-click="showAppLimitMessage(<c:out value="${ appLimit }"/>)">
                    Add Application
                </button>
            </c:if>
        </div>
    </c:if>

    <table class="table table-striped">
        <thead>
            <tr>
                <th class="medium first">Name</th>
                <th class="long">URL</th>
                <th class="short">Criticality</th>
                <th class="short">Open Vulns</th>
                <th class="short">Critical</th>
                <th class="short">High</th>
                <th class="short">Medium</th>
                <th class="short">Low</th>
                <th class="short">Info</th>
            </tr>
        </thead>
        <tbody id="applicationsTableBody">
            <tr ng-hide="applications" class="bodyRow">
                <td colspan="9" style="text-align:center;">No applications found.</td>
            </tr>
            <tr ng-show="applications"
                ng-repeat="app in applications" class="bodyRow">
                <td class="pointer ellipsis" ng-click="goToPage(app)" style="max-width:200px;" id="appName{{ $index }}">
                    <a id="appLink{{ $index }}"> {{ app.name }} </a>
                </td>
                <td class="ellipsis" style="max-width:200px;" id="appUrl{{ $index }}"> {{ app.url }} </td>
                <td id="appCriticality{{ $index }}"> {{ app.applicationCriticality.name }} </td>
                <td id="appTotalVulns{{ $index }}"> {{ app.totalVulnCount }} </td>
                <td id="appCriticalVulns{{ $index }}"> {{ app.criticalVulnCount }} </td>
                <td id="appHighVulns{{ $index }}"> {{ app.highVulnCount }} </td>
                <td id="appMediumVulns{{ $index }}"> {{ app.mediumVulnCount }} </td>
                <td id="appLowVulns{{ $index }}"> {{ app.lowVulnCount }} </td>
                <td id="appInfoVulns{{ $index }}"> {{ app.infoVulnCount }} </td>
            </tr>
        </tbody>
    </table>
</body>
