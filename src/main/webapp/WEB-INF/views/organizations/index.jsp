<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/bootstrap.min.js" media="screen"></script>
	<link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/bootstrap.min.css"/>
</head>

<body id="apps">
	<div id="helpText">A Team is a group of developers who are responsible for the same application or applications.</div>
	
	<c:if test='${ shouldChangePassword }'>
		<div id="passwordNag" style="width:600px;font-weight:bold;">Our records indicate that you haven't changed your 
			password since your account was created. You should change it by going here:
			<spring:url value="/configuration/users/password" var="passwordChangeUrl"/>
			<a id="changePasswordLink" href="${ fn:escapeXml(passwordChangeUrl) }">Change My Password</a>
		</div>
	</c:if>
	
	<h2>Teams</h2>
	<img src="<%=request.getContextPath()%>/images/ThreadFix_72.jpg">
	<img src="<%=request.getContextPath()%>/images/ThreadFix_72.jpg">

	<br>
	<a href="#myTeamModal" role="button" class="btn" data-toggle="modal" style="margin-bottom:8px">Add Team</a>
	<div id="myTeamModal" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h3 id="myModalLabel">New Team</h3>
		</div>
		<spring:url value="/organizations/new" var="saveUrl"/>
		<form:form modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
		<div class="modal-body">
			Name: <form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
				<form:errors path="name" cssClass="errors" />
		</div>
		<div class="modal-footer">
			<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
			<button type="submit" class="btn btn-primary">Add Team</button>
		</div>
		</form:form>
	</div>
	
	<div class="accordion" id="accordion2">
		<c:forEach var="org" items="${ organizationList }" varStatus="status">
		<div class="accordion-group">
			<div class="accordion-heading">
				<a class="accordion-toggle" data-toggle="collapse"
					data-parent="#accordion2" href="#collapse${ status.count }"><c:out value="${ org.name }"/></a>
			</div>
			<div id="collapse${ status.count }" class="accordion-body collapse">
				<div class="accordion-inner">
					<c:if test="${ empty org.applications }">
						No applications found.<br>
					</c:if>
					<c:forEach var="app" items="${ org.applications }" varStatus="status">
						<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
							<spring:param name="orgId" value="${ org.id }"/>
							<spring:param name="appId" value="${ app.id }"/>
						</spring:url>
						<spring:url value="/organizations/{orgId}" var="orgUrl">
							<spring:param name="orgId" value="${ org.id }"/>
						</spring:url>
						<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
							<spring:param name="orgId" value="${ org.id }"/>
							<spring:param name="appId" value="${ app.id }"/>
						</spring:url>
						<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
							<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a>
							<input id="fileInput" type="file" name="file" size="50" />
							<button class="btn" id="uploadScanButton" type="submit">Upload Scan</button>
						</form:form>
					</c:forEach>
					<a href="#myAppModal${ status.count }" role="button" class="btn" data-toggle="modal">Add Application</a>
					<span><a href="${ orgUrl }">View Team</a></span>
					<div id="myAppModal${ status.count }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<div class="modal-header">
							<button type="button" class="close" data-dismiss="modal"
								aria-hidden="true">X</button>
							<h3 id="myModalLabel">New Application</h3>
						</div>
						<spring:url value="/organizations/{orgId}/applications/new" var="saveUrl">
							<spring:param name="orgId" value="${ org.id }"/>
						</spring:url>
							<form:form modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
							<div class="modal-body">
								<table>
									<tr>
										<td>Name:</td> 
										<td>
											<form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
										  	<form:errors path="name" cssClass="errors" />
										</td>
									</tr>
									<tr>
										<td>URL:</td>
										<td>
											<form:input id="urlInput" path="url" size="50" maxlength="255" />
										  	<form:errors path="url" cssClass="errors" />
									  	</td>
									</tr>
									<tr>
										<td>Team:</td>
										<td><c:out value="${ org.name }"/></td>
									</tr>
									<tr>
										<td>Criticality:</td>
										<td>
											<form:select id="criticalityId" path="applicationCriticality.id">
												<form:options items="${applicationCriticalityList}" itemValue="id" itemLabel="name"/>
											</form:select>
											<form:errors path="applicationCriticality.id" cssClass="errors" />
										</td>
									</tr>
								</table>
							</div>
							<div class="modal-footer">
								<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
								<button type="submit" class="btn btn-primary">Add Application</button>
							</div>
						</form:form>
					</div>
				</div>
			</div>
		</div>
		</c:forEach>
	</div>
	
</body>
