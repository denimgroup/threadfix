<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Dashboard</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/dashboardController.js"></script>
</head>

<body class="dashboard">
	<h2>Dashboard</h2>
	
	<spring:url value="/organizations" var="teamsUrl"/>
	
	<c:if test="${ empty teams }">
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
		    <div class="alert">
			    <button type="button" class="close" data-dismiss="alert">&times;</button>
			    <strong>No teams found!</strong> To upload scans, first you need to create teams and applications.  
			    <a href="<c:out value="${ teamsUrl }"/>#myTeamModal">
			    	Get started
			    </a>
	  	 	</div>
	  	</security:authorize>
  	 	
		<security:authorize ifNotGranted="ROLE_CAN_MANAGE_TEAMS">
			<div class="alert alert-error">
				You don't have permission to access any ThreadFix applications or to create one for yourself. 
				Contact your administrator to get help.
			</div>
		</security:authorize>
	</c:if>

    <!-- Get the CSRF token so we can use it everywhere -->
    <spring:url value="" var="emptyUrl"/>

    <div ng-controller="DashboardController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'" class="container-fluid">
		<c:if test="${ canGenerateReports }">
			<div class="row-fluid">
			    <div class="span6">
			    	<spring:url value="/reports/9" var="reportsUrl"/>
			    	<h4>6 Month Vulnerability Burndown<span style="font-size:12px;float:right;">
			    		<a id="leftViewMore" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
			    	</h4>
			    	<div id="leftTileReport">
                        <div ng-show="leftReport" bind-html-unsafe="leftReport" class="tableReportDiv report-image"></div>
                        <div ng-hide="leftReport" ng-hide="leftReportFailed" class="team-report-wrapper report-image">
                            <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                        </div>
                        <div ng-show="leftReportFailed" class="team-report-wrapper report-image">
                            <div style="text-align: center; padding-top:120px;">
                                Report Failed
                            </div>
                        </div>
			    	</div>
			    </div>
			    
			     <div class="span6">
			     	<spring:url value="/reports/10" var="reportsUrl"/>
			    	<h4>Top 10 Vulnerable Applications <span style="font-size:12px;float:right;">
			    		<a id="rightViewMore" href="<c:out value="${ reportsUrl }"/>">View More</a></span>
			    	</h4>
                    <div id="rightTileReport">
                        <div ng-show="rightReport" bind-html-unsafe="rightReport" class="tableReportDiv report-image"></div>
                        <div ng-hide="rightReport" ng-hide="rightReportFailed" class="team-report-wrapper report-image">
                            <div style="float:right;padding-top:120px" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                        </div>
                        <div ng-show="rightReportFailed" class="team-report-wrapper report-image">
                            Report Failed
                        </div>
                    </div>
			    </div>
			</div>
		</c:if>
	    
	    <div class="row-fluid">
	    	<div class="row-fluid" style="padding-top:20px;">
			     <div class="span6">
			    	<h4>Recent Uploads</h4>
			    	<table class="table table-bordered thick-borders">
						<thead>
							<tr>
								<th class="thick-left">Date</th>
								<th colspan="2">Application</th>
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
								<td class="thick-left">
									<fmt:formatDate value="${ scan.importTime.time }" type="both" pattern="MM/dd/yy"/><br>
								</td>
								<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
			                       <spring:param name="orgId" value="${ scan.application.organization.id }"/>
			                       <spring:param name="appId" value="${ scan.application.id }"/>
				                </spring:url>
								<td class="no-left-border" id="application${ status.count }">
									<div style="width:240px;" class="ellipsis">
										<a style="text-decoration:underline;" id="scanApplicationLink${ status.count }" href="${ fn:escapeXml(appUrl) }">
											<c:out value="${ scan.applicationChannel.application.name }"/>
										</a>
									</div>
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
								<td class="thick-left" colspan="3">
									<span style="font-weight:bold;color:red;"><c:out value="${ scan.numberTotalVulnerabilities }"/></span> Vulnerabilities from
									<c:out value="${ scan.applicationChannel.channelType.name }"/> (<c:out value="${ scan.scannerType }"/>)
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
								<th class="thick-left">Application</th>
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
								<c:if test="${ not comment.vulnerability.hidden and 
										comment.vulnerability.active and 
										comment.vulnerability.application.active }">
									<tr class="bodyRow">
										<td class="thick-left" id="commentUser${ status.count }">
											<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
						                    	<spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }"/>
						                    	<spring:param name="appId" value="${ comment.vulnerability.application.id }"/>
											</spring:url>
											<div style="width:142px;" class="ellipsis">
												<a style="text-decoration:underline;" href="<c:out value="${ appUrl }"/>">
													<c:out value="${ comment.vulnerability.application.name }" />
												</a>
											</div>
										</td>
										<td class="no-left-border" id="commentVulnId${ status.count }">
											<div style="width:197px;" class="ellipsis">
												<c:out value="${ comment.vulnerability.genericVulnerability.name }" />
											</div>
										</td>
										<td class="no-left-border" id="viewMoreLink${ status.count }">
											<spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}" var="vulnUrl">
												<spring:param name="orgId" value="${ comment.vulnerability.application.organization.id }" />
												<spring:param name="appId" value="${ comment.vulnerability.application.id }" />
												<spring:param name="vulnId" value="${ comment.vulnerability.id }" />
											</spring:url>
											<div style="float:right;width:35px;">
												<a href="${ fn:escapeXml(vulnUrl) }#commentDiv${ comment.vulnerability.id }">
													View
												</a>
											</div>
										</td>
									</tr>
									<tr class="no-top-border">
										<td class="thick-left" colspan="3" id="commentText${ status.count }">
											<div class="vuln-comment-word-wrap ellipsis">
												<c:out value="${ comment.comment }" />
											</div>
										</td>
									</tr>
								</c:if>
							</c:forEach>
						</tbody>
					</table>
			    </div>
			</div>
	    </div>
	</div>
</body>
