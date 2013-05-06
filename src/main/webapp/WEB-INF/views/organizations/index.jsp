<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/teams_page.js"></script>
</head>

<body id="apps">
	<h2>Applications</h2>

	<spring:url value="/organizations/teamTable" var="tableUrl"/>
	<div id="teamTable" data-url="<c:out value="${ tableUrl }"/>" style="margin-bottom:8px;margin-top:10px;">
		<a id="addTeamModalButton" href="#myTeamModal" role="button" class="btn" 
				data-toggle="modal">Add Team</a>
		<a id="expandAllButton">Expand All</a>
		<a id="collapseAllButton">Collapse All</a>
	</div>
	
	<div id="myTeamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="formDiv">
			<%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
		</div>
	</div>
</body>
