<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><fmt:message key="mainMenu.title" /></title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
</head>

<body id="apps">
	<h2><c:out value="${ defect.application.defectTracker.name }"/> Defect <c:out value="${ defect.nativeId }"/> Details</h2>
	<c:out value="${ message }"/>
	Bug Status: <c:out value="${ defect.status }"/>
	<br/>
	<br/>
	<c:if test="${ not empty defect.defectURL }">
		Bug Tracker URL: <a href="${ fn:escapeXml(defect.defectURL) }"><c:out value="${fn:escapeXml(defect.defectURL)}"/></a>
		<br/><br/>
	</c:if>
	<spring:url value="../../../{appId}" var="appUrl">
		<spring:param name="appId" value="${ fn:escapeXml(defect.application.id) }" />
	</spring:url>
	<a href="${ fn:escapeXml(appUrl) }">Back to Application <c:out value="${ defect.application.name }"/></a>
	<br/>
	<br/>
	
	<table class="table table-striped sortable" id="anyid">
		<thead>
			<tr>
				<th class="first">If Merged</th>
			    <th>Generic Vulnerability</th>
				<th>Generic Severity</th>
				<th>Path</th>
				<th>Parameter</th>
				<th>WAF Rule</th>
				<th class="last unsortable">WAF Events</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty defect.vulnerabilities }">
			<tr class="bodyRow">
				<td colspan="8" style="text-align:center;">No vulnerabilities found.</td>
			</tr>
		</c:if>
		<c:forEach var="vuln" items="${ defect.vulnerabilities }">
			<tr class="bodyRow">
				<td>
					
					<c:if test="${ fn:length(vuln.findings) > 1 }">
						<spring:url value="../{vulnId}" var="vulnerabilityUrl">
							<spring:param name="vulnId" value="${ vuln.id }" />
				    	</spring:url>
				    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        	Yes
				    	</a>
					</c:if>
				</td>
				<td>
					<spring:url value="../{vulnId}" var="vulnerabilityUrl">
						<spring:param name="vulnId" value="${ vuln.id }" />
			    	</spring:url>
				    <a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        <c:out value="${ vuln.genericVulnerability.name }"/>
				    </a>
				</td>
				<td><c:out value="${ vuln.genericSeverity.displayName }"/></td>
				<td><c:out value="${ vuln.surfaceLocation.path }"/></td>
				<td><c:out value="${ vuln.surfaceLocation.parameter }"/></td>

				<td>
				<c:choose>
					<c:when test="${ not empty vuln.wafRules }">
						Yes
					</c:when>
					<c:otherwise>
						No
					</c:otherwise>
				</c:choose>
				</td>
				<td>
					<c:out value="${ vuln.noOfSecurityEvents }" />
				</td>
			</tr>
		</c:forEach>
		</tbody>
		<tfoot>
			<tr class="footer">
				<td colspan="8" class="pagination" style="text-align:right"></td>
			</tr>
		</tfoot>
	</table>
</body>
