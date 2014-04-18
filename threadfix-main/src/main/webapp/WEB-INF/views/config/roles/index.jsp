<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Manage Roles</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/roles-page-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
</head>

<body ng-controller="RolesPageController">
	<h2>Manage Roles</h2>

    <%@ include file="/WEB-INF/views/config/roles/form.jsp" %>
    <%@ include file="/WEB-INF/views/config/roles/newForm.jsp" %>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

    <div id="helpText">
		ThreadFix Roles determine functional capabilities for associated users.<br/>
	</div>
	
	<a id="createRoleModalLink" class="btn" ng-click="openNewRoleModal()">Create New Role</a>
	
	<div id="tableDiv">
		<%@ include file="/WEB-INF/views/config/roles/rolesTable.jsp" %>
	</div>
		
</body>
