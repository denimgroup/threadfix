<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript">
		function update() {
			$("#appSelect").html('');
			$("#appSelect").append('<option value="-1">New Application</option>');
			var options = '';
			
			<c:forEach var="organization" items="${organizationList}">
			    if("${organization.id}" === $("#orgSelect").val()) {
					<c:forEach var="application" items="${ organization.activeApplications}">
						options += '<option value="${ application.id}"><c:out value="${ application.name }"/></option>';
					</c:forEach>
			    }
			</c:forEach>

			$("#appSelect").append(options);
		};
	</script>
</head>

<body id="apps">
	<c:if test="${ not empty channels }">
	<security:authorize ifAllGranted="ROLE_CAN_MANAGE_TEAMS,ROLE_CAN_UPLOAD_SCANS,ROLE_CAN_MANAGE_APPLICATIONS">
	<h2>Quick Start</h2>
	
		<spring:url value="/organizations" var="uploadUrl"></spring:url>
		<form:form commandName="quickStartModel" method="post" 
				   action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
			<table class="dataTable">
				<tbody>
				<c:if test="${ not empty organizationList }">
					<tr>
						<td class="label">Team:</td>
						<td class="inputValue">
							<div id="orgDropDown">
								<form:select id="orgSelect" onclick="update();" path="organization.id" name="orgId">
									<option value="-1">New Team</option>
									<c:forEach var="organization" items="${ organizationList }">
										<c:if test="${ organization.active }">
										<option value="${ organization.id }">
											<c:out value="${ organization.name }"/>
										</option>
										</c:if>
									</c:forEach>
								</form:select>
							</div>
						</td>
						<td style="padding-left:5px">
							<form:errors path="organization.id" cssClass="errors" />
						</td>
					</tr>
				</c:if>
					<tr>
						<td class="label">New Team Name:</td>
						<td class="inputValue">
							<form:input id="urlInput" path="organization.name" class="focus" type="text" maxlength="255" size="50" value="Team 1" name="teamName"/>
						</td>
						<td style="padding-left:5px">
							<form:errors path="organization.name" cssClass="errors" />
						</td>
					</tr>
				<c:if test="${ not empty organizationList }">
					<tr>
						<td class="label">Application:</td>
						<td class="inputValue">
							<div id="appDropDown">
								<form:select path="application.id" id="appSelect" name="appId">
									<option value="-1">New Application</option>
								</form:select>
							</div>
						</td>
						<td style="padding-left:5px">
							<form:errors path="application.id" cssClass="errors" />
						</td>
					</tr>
				</c:if>
					<tr>
						<td class="label">New Application Name:</td>
						<td class="inputValue">
							<form:input path="application.name" id="urlInput" class="focus" type="text" maxlength="255" size="50" value="Application 1" name="appName"/>
						</td>
						<td style="padding-left:5px">
							<form:errors path="application.name" cssClass="errors" />
						</td>
					</tr>
					<tr>
						<td class="label">Scanner Type:</td>
						<td class="inputValue">
							<form:select path="channelType.id" id="channelSelect" name="channelId">
									<option value="-1">Auto-detect</option>
								<c:forEach var="channel" items="${ channels }">
									<option onclick="display(<c:out value="${ channel.id }"/>)" value="${ channel.id }"><c:out value="${ channel.name }"/></option>
								</c:forEach>
							</form:select>
							<c:forEach var="channelType" items="${ channels }">
								<c:if test="${ not empty channelType.exportInfo }">
									<span style="padding-left: 8px; display: none;" id="info${ channel.id }">
										<a href="javascript:alert('<c:out value='${ channelType.exportInfo }'/>');">Which file format do I need?</a>
									</span>
								</c:if>
							</c:forEach>
							<c:if test="${ not empty application.uploadableChannels }">
								<script>display(<c:out value="${ application.uploadableChannels[0].id}"/>);</script>
							</c:if>
						</td>
						<td style="padding-left:5px">
							<form:errors path="channelType.id" cssClass="errors" />
						</td>
					</tr>
					<tr>
						<td class="label">File:</td>
						<td class="inputValue">
							<form:input path="multipartFile" id="fileInput" type="file" name="file" size="50" />
						</td>
						<td style="padding-left:5px">
							<form:errors path="multipartFile" cssClass="errors" />
						</td>
					</tr>
				</tbody>
			</table>
			<br />
			<input id="uploadScanButton" type="submit" value="Quick Start" />
		</form:form>	
	</security:authorize>
	</c:if>
	
	<div style="padding-top:5px;padding-bottom:5px"></div>
	
	<h2>Teams</h2>
	<div id="helpText">A Team is a group of developers who are responsible for the same application or applications.</div>
	
	<c:if test='${ shouldChangePassword }'>
		<div id="passwordNag" style="width:600px;font-weight:bold;">Our records indicate that you haven't changed your 
			password since your account was created. You should change it by going here:
			<spring:url value="/configuration/users/password" var="passwordChangeUrl"/>
			<a id="changePasswordLink" href="${ fn:escapeXml(passwordChangeUrl) }">Change My Password</a>
		</div>
	</c:if>
	
	
	
	<div style="padding-top:5px;padding-bottom:5px"></div>
	
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Team Name</th>
				<th class="short">No. of Apps</th>
				<th class="short">Open Vulns</th>
				<th class="short">Critical</th>
				<th class="short">High</th>
				<th class="short">Medium</th>
				<th class="short last">Low</th>
			</tr>
		</thead>
		<tbody id="orgTableBody">
		<c:if test="${ empty organizationList }">
			<tr class="bodyRow">
				<td colspan="8" style="text-align:center;">No teams found.</td>
			</tr>
		</c:if>
		<c:forEach var="org" items="${ organizationList }">
			<tr class="bodyRow">
				<td class="details">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ org.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(orgUrl) }">
						<c:out value="${ org.name }"/>
					</a> 
				</td>
				<td>
					<c:out value="${ fn:length(org.activeApplications) }" />
				</td>
				<td><c:out value="${ org.vulnerabilityReport[5] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[4] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[3] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[2] }"/></td>
				<td><c:out value="${ org.vulnerabilityReport[1] }"/></td>
			</tr>
		</c:forEach>
			<tr class="footer">
				<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
					<td colspan="4" class="first">
						<a id="addOrganization" href="<spring:url value="/organizations/new" />">Add Team</a>
					</td>
					<td colspan="3" class="last pagination" style="text-align:right"></td>
				</security:authorize>
				<security:authorize ifNotGranted="ROLE_CAN_MANAGE_TEAMS">
					<td colspan="7" class="last pagination" style="text-align:right"></td>
				</security:authorize>
			</tr>
		</tbody>
	</table>
	<br/>
</body>
