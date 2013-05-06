<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<a id="addTeamModalButton" href="#myTeamModal" role="button" class="btn" data-toggle="modal" 
	data-default-show="<c:out value="${ showTeamModal }"/>">Add Team</a>
<a class="btn" id="expandAllButton">Expand All</a>
<a class="btn" id="collapseAllButton">Collapse All</a>

<c:if test="${ not empty organizationList }">
<table class="table table-hover white-inner-table">
	<thead>
		<tr>
			<th style="width:8px"></th>
			<th>Name</th>
			<th style="width:70px;"></th>
		</tr>
	</thead>
	<c:forEach var="organization" items="${ organizationList }" varStatus="status">
		<tr id="teamRow${ organization.id }" class="pointer" data-target-div="teamInfoDiv${ organization.id}"
				data-caret-div="caret${ organization.id }" data-report-div="reportDiv${organization.id}">
			<td id="teamCaret${ organization.id }" class="expandableTrigger">
				<span id="caret${ organization.id }" class="caret-right"></span>
			</td>
			<td class="expandableTrigger" id="teamName${ status.count }">
				<c:out value="${ organization.name }"/>
			</td>
			<td>
				<spring:url value="/organizations/{orgId}" var="organizationUrl">
					<spring:param name="orgId" value="${ organization.id }"/>
				</spring:url>
				<a style="text-decoration:none" id="organizationLink${ organization.id }" href="<c:out value="${ organizationUrl }"/>">View Team</a>
			</td>
		</tr>
		<tr class="grey-background">
			<td colspan="3">
				<div id="teamInfoDiv${organization.id}" class="collapse">
					<c:if test="${ organization.vulnerabilityReport[5] != 0 }">
						<spring:url value="/organizations/{orgId}/getReport" var="reportUrl">
							<spring:param name="orgId" value="${ organization.id }"/>
						</spring:url>
						<div style="float:right;margin-right:-50px;margin-top:-40px;" id="reportDiv${organization.id}" data-url="<c:out value="${ reportUrl }"/>"></div>
					</c:if>
				
					<div id="teamAppTableDiv${ status.count }">
					<c:if test="${ empty organization.applications }">
						No applications found.
					</c:if>
					<c:if test="${ not empty organization.applications }">
						<table id="teamAppTable${ status.count }">
							<thead>
								<tr>
									<th style="width:70px;"></th>
									<th class="centered">#Vulns</th>
									<th class="centered">Critical</th>
									<th class="centered">High</th>
									<th class="centered">Medium</th>
									<th class="centered">Low</th>
									<th class="centered">Info</th>
									<th></th>
								</tr>
							</thead>
						<c:forEach var="application" items="${ organization.applications }" varStatus="innerStatus">
							<c:if test="${ application.active }">
								<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
									<spring:param name="orgId" value="${ organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
								</spring:url>
								<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
									<spring:param name="orgId" value="${ organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
								</spring:url>
								<tr class="app-row">
									<td style="padding:5px;word-wrap: break-word;">
										<div style="word-wrap: break-word;max-width:120px;text-align:left;">
											<a id="applicationLink${ status.count }-${ innerStatus.count }" href="${ fn:escapeXml(appUrl) }">
												<c:out value="${ application.name }"/>
											</a>
										</div>
									</td>
									<td class="centered" id="numTotalVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[5] }"/></td>
									<td class="centered" id="numCriticalVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[4] }"/></td>
									<td class="centered" id="numHighVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[3] }"/></td>
									<td class="centered" id="numMediumVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[2] }"/></td>
									<td class="centered" id="numLowVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[1] }"/></td>
									<td class="centered" id="numInfoVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[0] }"/></td>
									<td class="centered" style="padding:5px;">
										<a id="uploadScanModalLink${ status.count }-${ innerStatus.count }" href="#uploadScan${ application.id }" role="button" class="btn" data-toggle="modal">Upload Scan</a>
										<%@ include file="/WEB-INF/views/applications/modals/uploadScanModal.jsp" %>
									</td>
								</tr>
							</c:if>
						</c:forEach>
								<tr class="totalsRow">
									<td class="totals">
										Totals
									</td>
									<td id="numTotalVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[5] }"/></td>
									<td id="numCriticalVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[4] }"/></td>
									<td id="numHighVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[3] }"/></td>
									<td id="numMediumVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[2] }"/></td>
									<td id="numLowVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[1] }"/></td>
									<td id="numInfoVulns${ status.count }"><c:out value="${ organization.vulnerabilityReport[0] }"/></td>
									<td></td>
								</tr>
						</table>
					
					</c:if>
					
					<div style="margin-top:10px;margin-bottom:7px;">
						<a id="addApplicationModalButton${ organization.id }" href="#myAppModal${ organization.id }" role="button" class="btn" data-toggle="modal">Add Application</a>
					</div>
					</div>
					<div id="myAppModal${ organization.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<div id="formDiv${ organization.id }">
							<spring:url value="/organizations/{orgId}/modalAddApp" var="saveUrl">
								<spring:param name="orgId" value="${ organization.id }"/>
							</spring:url>
							<%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
						</div>
					</div>
				</div>
			</td>
		</tr>
	</c:forEach>
</table>
</c:if>
