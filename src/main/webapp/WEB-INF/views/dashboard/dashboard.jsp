<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Dashboard</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/dashboard_page.js"></script>
</head>

<body class="dashboard">
	<h2>Dashboard</h2>
	
	<spring:url value="/organizations/withModal" var="teamsUrl"/>
	
	<c:if test="${ empty teams }">
	    <div class="alert">
		    <button type="button" class="close" data-dismiss="alert">&times;</button>
		    <strong>No teams found!</strong> To upload scans, first you need to create teams and applications.  
		    <a href="<c:out value="${ teamsUrl }"/>#myTeamModal">
		    	Get started
		    </a>
  	 	</div>
	</c:if>
	
	<div class="container-fluid">
	
		<div class="row-fluid">
		    <div class="span6">
		    	<spring:url value="/reports/9" var="reportsUrl"/>
		    	<h4>6 Month Vulnerability Burndown<span style="font-size:12px;float:right;">
		    		<a id="leftViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
		    	</h4>
		    	<spring:url value="/dashboard/leftReport" var="reportsUrl"/>
				<form id="leftReportForm" action="<c:out value="${ reportsUrl }"/>"></form>
		    	<div id="leftTileReport">
		    		<%@ include file="/WEB-INF/views/reports/loading.jspf" %>
		    	</div>
		    </div>
		    
		     <div class="span6">
		     	<spring:url value="/reports/10" var="reportsUrl"/>
		    	<h4>Top 10 Vulnerable Applications <span style="font-size:12px;float:right;">
		    		<a id="rightViewMore" style="display:none" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
		    	</h4>
		    	<spring:url value="/dashboard/rightReport" var="reportsUrl"/>
				<form id="rightReportForm" action="<c:out value="${ reportsUrl }"/>"></form>
		    	<div id="rightTileReport">
		    		<%@ include file="/WEB-INF/views/reports/loading.jspf" %>
		    	</div>
		    </div>
		</div>
	    
	    <div class="row-fluid">
	    	<div class="row-fluid" style="padding-top:20px;">
			     <div class="span6">
			    	<h4>Recent Scans</h4>
			    	<table class="table table-bordered thick-borders">
						<thead>
							<tr>
								<th colspan="2" class="thick-left">Application</th>
							</tr>
						</thead>
						<tbody id="wafTableBody">
						<c:if test="${ empty recentScans }">
							<tr class="bodyRow">
								<td class="thick-left" colspan="4" style="text-align:center;">No scans found.</td>
							</tr>
						</c:if>
						<c:forEach var="scan" items="${ recentScans }" varStatus="status">
							<tr class="bodyRow">
								<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
			                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
			                       <spring:param name="appId" value="${ scan.application.id }"/>
				                </spring:url>
								<td class="thick-left" id="application${ status.count }">
									<a style="text-decoration:underline;" id="scanApplicationLink${ status.count }" href="${ fn:escapeXml(appUrl) }">
										<c:out value="${ scan.applicationChannel.application.name }"/>
									</a>
								</td>
								<td class="no-left-border" id="channelType${ status.count }">
									<spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="detailUrl">
					                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
					                       <spring:param name="appId" value="${ scan.application.id }"/>
					                       <spring:param name="scanId" value="${ scan.id }"/>
					                </spring:url>
					                <div style="float:right;width:70px;">
										<a id="scanLink${ status.count }" id="importTime${ status.count }" href="${ fn:escapeXml(detailUrl) }">
											View Scan
										</a>
									</div>
								</td>
							</tr>
							<tr class="no-top-border">
								<td class="thick-left">
									<fmt:formatDate value="${ scan.importTime.time }" type="both" pattern="yy/MM/dd hh:mm"/><br>
									<c:out value="${ scan.applicationChannel.channelType.name }"/> (<c:out value="${ scan.scannerType }"/>)<br>
									<c:out value="${ scan.numberTotalVulnerabilities }"/> Vulnerabilities found
								</td>
							</tr>
						</c:forEach>
						</tbody>
					</table>
			    </div>
			    
			    <div class="span6">
			    	<h4>Recent Comments</h4>
			    	<table class="table table-bordered thick-borders">
						<thead>
							<tr>
								<th class="thick-left">User</th>
								<th colspan="2">Vulnerability</th>
							<tr>
						</thead>
						<tbody>
							<c:if test="${ empty recentComments }">
								<tr>
									<td style="text-align:center" class="thick-left" colspan="3">No comments found.</td>
								</tr>
							</c:if>
							<c:forEach var="comment" items="${ recentComments }" varStatus="status">
								<tr class="bodyRow">
									<td class="thick-left" id="commentUser${ status.count }"><c:out value="${ comment.user.name }" /></td>
									<td class="no-left-border" id="commentVulnId${ status.count }">
										<c:out value="${ comment.vulnerability.id }" />
									</td>
									<td class="no-left-border" id="viewMoreLink${ status.count }">
										<spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}" var="vulnUrl">
											<spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }" />
											<spring:param name="appId" value="${ comment.vulnerability.application.id }" />
											<spring:param name="vulnId" value="${ comment.vulnerability.id }" />
										</spring:url>
										<div style="float:right;width:70px;">
											<a href="${ fn:escapeXml(vulnUrl) }#commentDiv${ comment.vulnerability.id }">
												View More
											</a>
										</div>
									</td>
								</tr>
								<tr class="no-top-border">
									<td class="thick-left" colspan="3" id="commentText${ status.count }"><c:out value="${ comment.comment }" /></td>
								</tr>
							</c:forEach>
						</tbody>
					</table>
			    </div>
			</div>
	    </div>
	</div>
</body>
