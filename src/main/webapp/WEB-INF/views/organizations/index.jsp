<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/teams_page.js"></script>
</head>

<body id="apps">
	<h2>Teams Index</h2>

	<spring:url value="/organizations/teamTable" var="tableUrl"/>
	<div id="teamTable" data-url="<c:out value="${ tableUrl }"/>">
		<a id="addTeamModalButton" href="#myTeamModal" role="button" class="btn" data-toggle="modal" style="margin-bottom:8px;margin-top:10px;">Add Team</a>
	</div>
	
	<div id="myTeamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="formDiv">
			<%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
		</div>
	</div>
</body>
