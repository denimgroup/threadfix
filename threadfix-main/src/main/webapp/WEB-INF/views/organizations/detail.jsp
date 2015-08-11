<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ organization.name }"/></title>
	<cbs:cachebustscript src="/scripts/team-detail-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/vuln-search-controller.js"/>
    <cbs:cachebustscript src="/scripts/vuln-search-tree-controller.js"/>
    <cbs:cachebustscript src="/scripts/bulk-operations-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/report-filter-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/vuln-summary-modal-controller.js"/>
    <c:forEach items="${ reportJsPaths }" var="reportJs">
        <script type="text/javascript" src="${ reportJs }"></script>
    </c:forEach>
    <c:if test="${isEnterprise}">
        <cbs:cachebustscript src="/scripts/history-table-controller.js"/>
    </c:if>
</head>

<body ng-controller="TeamDetailPageController"
      id="apps">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
    <%@ include file="/WEB-INF/views/organizations/editTeamForm.jsp" %>
    <%@ include file="/WEB-INF/views/config/users/permissibleUsers.jsp" %>
    <%@ include file="/WEB-INF/views/reports/vulnSummaryModal.jsp" %>
    <%@ include file="/WEB-INF/views/applications/forms/vulnCommentForm.jsp"%>
    <%@ include file="/WEB-INF/views/applications/forms/vulnTaggingForm.jsp"%>

    <ul class="breadcrumb">
        <li><a href="<spring:url value="/teams"/>">Applications Index</a> <span class="divider">/</span></li>
        <li class="active">Team: {{ team.name }}</li>
    </ul>
    <h2 id="name" style="padding-top:5px;">
        {{ team.name }}
        <c:if test="${ canManageTeams || canManageUsers || canManageVulnFilters }">
            <div id="btnDiv1" class="btn-group">
                <button id="actionButton" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
                <ul class="dropdown-menu">
                    <c:if test="${ canManageTeams }">
                        <li>
                            <a id="teamModalButton" href="#" ng-click="openEditModal()">Edit / Delete</a>
                        </li>
                    </c:if>
                    <c:if test="${ canManageVulnFilters }">
                        <li>
                            <spring:url value="{orgId}/filters" var="filterUrl">
                                <spring:param name="orgId" value="${ organization.id }"/>
                            </spring:url>
                            <a id="editfiltersButton1" href="<c:out value='${ filterUrl }'/>" data-toggle="modal">
                                Customize ThreadFix Vulnerability Types and Severities
                            </a>
                        </li>
                    </c:if>
                    <c:if test="${ canManageUsers && isEnterprise }">
                        <li><a id="userListModelButton" href="#" ng-click="showUsers()">View Permissible Users</a></li>
                    </c:if>
                </ul>
            </div>
        </c:if>
    </h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>

    <div class="container-fluid">
        <div class="row-fluid">
            <c:set var="csrfToken" value="${ emptyUrl }" scope="request"/>
            <jsp:include page="${ config.teamTopLeft.jspFilePath }"/>
            <jsp:include page="${ config.teamTopRight.jspFilePath }"/>
        </div>
    </div>

    <tabset style="margin-top:10px;">
        <tab heading="{{ countApps }} Applications" active="showAppsTab" >
            <%@ include file="applicationsTable.jsp" %>
        </tab>
        <tab heading="{{ vulnerabilityCount }} Vulnerabilities" active="showVulnTab" ng-click="clickVulnTab()" >
            <%@ include file="../vulnerabilities/vulnSearchControls.jsp" %>
        </tab>
        <c:if test="${isEnterprise}">
            <jsp:include page="/app/organizations/${ organization.id }/history"/>
        </c:if>

    </tabset>

</body>
