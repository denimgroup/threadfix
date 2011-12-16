<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><fmt:message key="mainMenu.title" /></title>
	<meta name="heading" content="<fmt:message key='mainMenu.heading'/>" />
</head>

<body id="apps">
	<h2>Merge Findings</h2>
	
	<table class="dataTable">
		<tr>
			<td class="label">Severity / Generic Severity:</td>
			<td class="inputValue"><c:out value="${ finding.channelSeverity.name }"/> / <c:out value="${ finding.channelSeverity.severityMap.genericSeverity.name }"/></td>
		</tr>
		<tr>
			<td class="label">Vulnerability Type:</td>
			<td class="inputValue"><c:out value="${ finding.channelVulnerability.name }"/></td>
		</tr>
		<tr>
			<td class="label">Generic Vulnerability Type:</td>
			<td class="inputValue"><c:out value="${ finding.channelVulnerability.genericVulnerability.name }"/></td>
		</tr>
		<tr>
			<td class="label">Vulnerability ID:</td>
			<spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}" var="vulnUrl">
				<spring:param name="orgId" value="${ finding.vulnerability.application.organization.id }"/>
				<spring:param name="appId" value="${ finding.vulnerability.application.id }"/>
				<spring:param name="vulnId" value="${ finding.vulnerability.id }"/>
			</spring:url>
			<td class="inputValue"><a href="${ fn:escapeXml(vulnUrl) }"><c:out value="${ finding.vulnerability.id }"/></a></td>
		</tr>
		<tr>
			<td class="label">Parameter:</td>
			<td class="inputValue"><c:out value="${ finding.surfaceLocation.parameter }"/></td>
		</tr>
		<tr>
			<td class="label">Path:</td>
			<td class="inputValue"><c:out value="${ finding.surfaceLocation.path }"/></td>
		</tr>
	</table>
	<spring:url value="setVulnerability" var="formUrl"/>
	<form:form modelAttribute="similarFindings" action="${ fn:escapeXml(formUrl) }">
		<h3>Same Variable or Location</h3>
		<table class="formattedTable">
			<thead>
				<tr>
					<th class="first">Select</th>
					<th>Vuln ID</th>
					<th>Generic Vuln Name</th>
					<th>Path</th>
					<th class="last">Parameter</th>
				</tr>
			</thead>
			<tbody>
		<c:choose>
			<c:when test="${ empty similarVulns }">
				<tr class="bodyRow">
					<td colspan="5" style="text-align:center;">No similar vulnerabilities found.</td>
				</tr>
			</c:when>
			<c:otherwise>
			<c:forEach var="vulnerability" items="${ similarVulns }">
				<tr class="bodyRow">
					<td style="text-align:center">
						<input type="radio" name="vulnerabilityId" value="${ vulnerability.id }"></input>
					</td>
					<td style="text-align:center">
						<c:out value="${ vulnerability.id }"/>
					</td>
					<td><c:out value="${ vulnerability.genericVulnerability.name }"/></td>
				<c:forEach var="finding" items="${ vulnerability.findings }">
					<td><c:out value="${ finding.surfaceLocation.path }"/></td>
					<td><c:out value="${ finding.surfaceLocation.parameter }"/></td>
				</c:forEach>
				</tr>
			</c:forEach>
			</c:otherwise>
		</c:choose>
				<tr class="footer">
					<td colspan="5" class="pagination" style="text-align:right"></td>
				</tr>
			</tbody>
		</table>
		
		<h3>Same Generic Type</h3>
		<table class="formattedTable">
			<thead>
				<tr>
					<th class="first">Select</th>
					<th>Vuln ID</th>
					<th>Generic Vuln Name</th>
					<th>Path</th>
					<th class="last">Parameter</th>
				</tr>
			</thead>
			<tbody>
		<c:choose>
			<c:when test="${ empty sameGenericVulns }">
				<tr class="bodyRow">
					<td colspan="5" style="text-align:center;">No similar vulnerabilities found.</td>
				</tr>
			</c:when>
			<c:otherwise>
			<c:forEach var="vulnerability" items="${ sameGenericVulns }">
				<tr class="bodyRow">
					<td style="text-align:center">
						<input type="radio" name="vulnerabilityId" value="${ vulnerability.id }"></input>
					</td>
					<td style="text-align:center">
						<c:out value="${ vulnerability.id }"/>
					</td>
					<td><c:out value="${ vulnerability.genericVulnerability.name }"/></td>
					<c:forEach var="finding" items="${ vulnerability.findings }">
						<td><c:out value="${ finding.surfaceLocation.path }"/></td>
						<td><c:out value="${ finding.surfaceLocation.parameter }"/></td>
					</c:forEach>
				</tr>
			</c:forEach>
			</c:otherwise>
		</c:choose>
				<tr class="footer">
					<td colspan="5" class="pagination" style="text-align:right"></td>
				</tr>
			</tbody>
		</table>
		<br/>
		<input type="submit" value="Submit Merge">
	</form:form>
</body>
