<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Dashboard</title>
</head>

<body class="dashboard">
	<h2>Dashboard</h2>
	
	<div style="width:1000px;height:1200px;">
		<div class="alert">
		    <button type="button" class="close" data-dismiss="alert">&times;</button>
		    <strong>Warning!</strong> A Defect Submission failed. <a href="#">Check your configuration</a>
	    </div>    
	    
	    <div class="alert">
		    <button type="button" class="close" data-dismiss="alert">&times;</button>
		    <strong>Warning!</strong> jdoe@denimgroup has requested a user account. <a href="#">Add One</a>
	    </div>
	    
	    <div class="left-tile">
	    	<h4>Vulnerability Breakdown</h4>
	    	
	    	<img src="<%=request.getContextPath()%>/images/graph1.PNG">
	    </div>
	    
	     <div style="margin-left:500px;">
	    	<h4>Top 10 Vulnerable Applications</h4>
	    		
	    	<img src="<%=request.getContextPath()%>/images/graph2.PNG">
	    </div>
	    
	    <div style="margin-top:100px">
		     <div class="left-tile">
		    	<h4 style="margin-top:0px;">Recent Scans</h4>
		    	<table class="table table-striped">
					<thead>
						<tr>
							<th>Application</th>
							<th>Channel</th>
							<th>Scan Date</th>
							<th class="short">Total Vulns</th>
						</tr>
					</thead>
					<tbody id="wafTableBody">
					<c:if test="${ empty recentScans }">
						<tr class="bodyRow">
							<td colspan="4" style="text-align:center;">No scans found.</td>
						</tr>
					</c:if>
					<c:forEach var="scan" items="${ recentScans }" varStatus="status">
						<tr class="bodyRow">
							<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
		                       <spring:param name="appId" value="${ scan.application.id }"/>
			                </spring:url>
							<td id="application${ status.count }">
								<a id="scanApplicationLink${ status.count }" href="${ fn:escapeXml(appUrl) }">
									<c:out value="${ scan.applicationChannel.application.name }"/>
								</a>
							</td>
							<td id="channelType${ status.count }">
								<c:out value="${ scan.applicationChannel.channelType.name }"/>
							</td>
							<td>
						        <spring:url value="/organizations/{orgId}/applications/{appId}/scans/{scanId}" var="detailUrl">
				                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
				                       <spring:param name="appId" value="${ scan.application.id }"/>
				                       <spring:param name="scanId" value="${ scan.id }"/>
				                </spring:url>
								<a id="scanLink${ status.count }" id="importTime${ status.count }" href="${ fn:escapeXml(detailUrl) }">
									<fmt:formatDate value="${ scan.importTime.time }" type="both" pattern="yy/MM/dd_hh:mm"/>
								</a>
							</td>
							<td id="numTotalVulnerabilities${ status.count }">
								<c:out value="${ scan.numberTotalVulnerabilities }"/>
							</td>
						</tr>
					</c:forEach>
					</tbody>
				</table>
		    </div>
		    
		     <div style="margin-left:500px;">
		    	<h4>Recent Comments</h4>
		    	<table class="table table-striped">
					<thead>
						<tr>
							<th>User</th>
							<th>Vulnerability</th>
							<th class="last">Comment</th>
						<tr>
					</thead>
					<tbody>
						<c:if test="${ empty recentComments }">
							<tr>
								<td colspan="3">No comments were retrieved.</td>
							</tr>
						</c:if>
						<c:forEach var="comment" items="${ recentComments }" varStatus="status">
							<tr class="bodyRow">
								<td id="commentUser${ status.count }"><c:out value="${ comment.user.name }" /></td>
								<td id="commentVuln${ status.count }">
									<spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}" var="vulnUrl">
										<spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }" />
										<spring:param name="appId" value="${ comment.vulnerability.application.id }" />
										<spring:param name="vulnId" value="${ comment.vulnerability.id }" />
									</spring:url>
									<a href="${ fn:escapeXml(vulnUrl) }">
										<c:out value="${ comment.vulnerability.id }" />
									</a>
								</td>
								<td id="commentText${ status.count }"><c:out value="${ comment.comment }" /></td>
							</tr>
						</c:forEach>
					</tbody>
				</table>
		    </div>
	    </div>
	</div>
</body>
