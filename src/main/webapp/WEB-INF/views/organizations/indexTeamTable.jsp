<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty organizationList }">
<table class="table table-hover white-inner-table">
	<thead>
		<tr>
			<th>Name</th>
		</tr>
	</thead>
	<c:forEach var="organization" items="${ organizationList }" varStatus="status">
		<tr data-toggle="collapse" data-target="#teamInfoDiv${organization.id}">
			<td id="teamName${ status.count }">
				<c:out value="${ organization.name }"/>
			</td>
		</tr>
		<tr class="expandable">
			<td colspan="7">
				<div id="teamInfoDiv${organization.id}" class="collapse"> 
					<c:if test="${ empty organization.applications }">
						No applications found.<br>
					</c:if>
					<c:if test="${ not empty organization.applications }">
						<table>
						<c:forEach var="application" items="${ organization.applications }">
							<c:if test="${ application.active }">
								<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
									<spring:param name="orgId" value="${ organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
								</spring:url>
								<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
									<spring:param name="orgId" value="${ organization.id }"/>
									<spring:param name="appId" value="${ application.id }"/>
								</spring:url>
								<thead>
									<tr>
										<th></th>
										<th>Open Vulns</th>
										<th>Critical</th>
										<th>High</th>
										<th>Medium</th>
										<th>Low</th>
									</tr>
								</thead>
								<tr>
									<td style="padding:5px;">
										<a id="applicationLink${ application.id }" href="${ fn:escapeXml(appUrl) }">
											<c:out value="${ application.name }"/>
										</a>
									</td>
									<td id="numTotalVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[5] }"/></td>
									<td id="numCriticalVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[4] }"/></td>
									<td id="numHighVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[3] }"/></td>
									<td id="numMediumVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[2] }"/></td>
									<td id="numLowVulns${ status.count }"><c:out value="${ application.vulnerabilityReport[1] }"/></td>
									<td style="padding:5px;">
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
									<td></td>
								</tr>
						</table>
					</c:if>
					<spring:url value="/organizations/{orgId}" var="organizationUrl">
						<spring:param name="orgId" value="${ organization.id }"/>
					</spring:url>
					<div style="margin-top:10px;margin-bottom:7px;">
						<a id="addApplicationModalButton${ organization.id }" href="#myAppModal${ organization.id }" role="button" class="btn" data-toggle="modal">Add Application</a>
						<span style="padding-left:8px;">
							<a id="organizationLink${ organization.id }" href="<c:out value="${ organizationUrl }"/>">View Team</a>
						</span>
					</div>
					<div id="myAppModal${ organization.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<div id="formDiv${ organization.id }">
							<%@ include file="/WEB-INF/views/applications/forms/newApplicationForm.jsp" %>
						</div>
					</div>
				</div>
			</td>
		</tr>
	</c:forEach>
</table>
</c:if>
