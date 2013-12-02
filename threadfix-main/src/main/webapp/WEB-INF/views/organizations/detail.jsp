<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ organization.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/sortable_us.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/team_detail_page.js"></script>
</head>

<body id="apps">
	<ul class="breadcrumb">
	    <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>
	    <li class="active">Team: <c:out value="${ organization.name }"/></li>
    </ul>
	<h2 id="name" style="padding-top:5px;">
		<c:out value="${ organization.name }"/>
		<c:if test="${ canManageTeams || canManageUsers }">
   			<div id="btnDiv1" class="btn-group">
				<button id="actionButton" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
				<ul class="dropdown-menu">									
					<c:if test="${ canManageTeams}">
						<li>
							<a id="teamModalButton" href="#teamModal" data-toggle="modal">Edit / Delete</a>
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
					<c:if test="${ canManageUsers && enterprise}">				
						<li><a id="userListModelButton" href="#usersModal" data-toggle="modal">View Permissible Users</a></li>
					</c:if>
				</ul>
			</div>
		</c:if>
	</h2>
	
	<div id="teamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="editFormDiv">
			<%@ include file="/WEB-INF/views/organizations/editTeamForm.jsp" %>
		</div>
	</div>
	<div id="usersModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div id="editFormDiv">
			<%@ include file="/WEB-INF/views/config/users/permissibleUsers.jsp" %>
		</div>
	</div>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	
	<c:if test="${ canGenerateReports }">
		<div class="container-fluid">
			<div class="row-fluid">
			    <div class="span6">
			    	<h4>
			    		6 Month Vulnerability Burndown
			    		<spring:url value="/reports/9/{orgId}" var="reportsUrl">
			    			<spring:param name="orgId" value="${ organization.id }"/>
			    		</spring:url>
						<span style="font-size:12px;float:right;">
				    		<a id="leftViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a>
				    	</span>
			    	</h4>
			    	<spring:url value="/dashboard/leftReport" var="reportsUrl"/>
					<form id="leftReportForm" action="<c:out value="${ reportsUrl }"/>">
						<input style="display:none" name="orgId" value="<c:out value="${ organization.id }"/>"/>
					</form>
			    	<div id="leftTileReport">
			    		<%@ include file="/WEB-INF/views/reports/loading.jspf" %>
			    	</div>
			    </div>
			    
			     <div class="span6">
			    	<h4>
			    		Top 10 Vulnerable Applications
			    		<spring:url value="/reports/10/{orgId}" var="reportsUrl">
			    			<spring:param name="orgId" value="${ organization.id }"/>
			    		</spring:url>
				    	<span style="font-size:12px;float:right;">
				    		<a id="rightViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a>
			    		</span>
			    	</h4>
			    	<spring:url value="/dashboard/rightReport" var="reportsUrl"/>
					<form id="rightReportForm" action="<c:out value="${ reportsUrl }"/>">
						<input style="display:none" name="orgId" value="<c:out value="${ organization.id }"/>"/>
					</form>
			    	<div id="rightTileReport">
			    		<%@ include file="/WEB-INF/views/reports/loading.jspf" %>
			    	</div>
			    </div>
			</div>
		</div>
	</c:if>
	
	<h3 style="padding-top:5px;">Applications</h3>
	<c:if test="${ canManageApplications }">
		<div style="margin-top:10px;margin-bottom:7px;">
			<a id="addApplicationModalButton${ organization.id }" href="#myAppModal${ organization.id }" role="button" class="btn" data-toggle="modal">Add Application</a>
		</div>
		<div id="myAppModal${ organization.id }" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
			<div id="formDiv${ organization.id }">
				<%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
			</div>
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
			<c:choose>
				<c:when test="${empty apps}">
					<tr class="bodyRow">
						<td colspan="9" style="text-align:center;">No applications found.</td>
					</tr>
				</c:when>
				<c:otherwise>
					<c:forEach var="app" items="${ apps }" varStatus="status">
					<tr class="bodyRow">
						<td style="max-width:200px;" class="ellipsis" id="appName${ status.count }">
							<spring:url value="{orgId}/applications/{appId}" var="appUrl">
								<spring:param name="orgId" value="${ organization.id }"/>
								<spring:param name="appId" value="${ app.id }"/>
							</spring:url>
							<a id="appLink${ status.count }" href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a>
						</td>
						<td class="ellipsis" style="max-width:200px;" id="appUrl${ status.count }"><c:out value="${ app.url }"/></td>
						<td id="appCriticality${ status.count }"><c:out value="${ app.applicationCriticality.name }"/></td>
						<td id="appTotalVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[5] }"/></td>
						<td id="appCriticalVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[4] }"/></td>
						<td id="appHighVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[3] }"/></td>
						<td id="appMediumVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[2] }"/></td>
						<td id="appLowVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[1] }"/></td>
						<td id="appInfoVulns${ status.count }"><c:out value="${ app.vulnerabilityReport[0] }"/></td>
					</tr>
					</c:forEach>
				</c:otherwise>
			</c:choose>
		</tbody>
	</table>
</body>
