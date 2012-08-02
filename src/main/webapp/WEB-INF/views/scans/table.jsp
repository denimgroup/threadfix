<%@ include file="/common/taglibs.jsp"%>

	<h3 style="padding-top:8px">Successfully Mapped Findings:</h3>

	<spring:url value="{scanId}/table" var="tableUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<c:if test="${ numFindings > 100 }">
	<div style="padding-bottom:8px">	
		<c:if test="${ page > 4 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', 1)">First</a>
		</c:if>
	
		<c:if test="${ page >= 4 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 3 })"><c:out value="${ page - 3 }"/></a>
		</c:if>
	
		<c:if test="${ page >= 3 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 2 })"><c:out value="${ page - 2 }"/></a>
		</c:if>
		
		<c:if test="${ page >= 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 1 })"><c:out value="${ page - 1 }"/></a>
		</c:if>
		
		<c:out value="${ page }"/>
	
		<c:if test="${ page <= numPages }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 1 })"><c:out value="${ page + 1 }"/></a>
		</c:if>
		
		<c:if test="${ page <= numPages - 1 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 2 })"><c:out value="${ page + 2 }"/></a>
		</c:if>
		
		<c:if test="${ page <= numPages - 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 3 })"><c:out value="${ page + 3 }"/></a>
		</c:if>
		
		<c:if test="${ page < numPages - 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ numPages + 1 })">Last (<c:out value="${ numPages + 1}"/>)</a>
		</c:if>
		
		<a href="javascript:refillElementDropDownPage('#toReplace', '${ tableUrl }')">Go to page</a>
		<input type="text" id="pageInput" />
	</div>
	</c:if>

	<table class="formattedTable sortable" id="1">
		<thead>
			<tr>
				<th class="first">Severity</th>
				<th>Vulnerability Type</th>
				<th>Path</th>
				<th>Parameter</th>
				<th>Vulnerability Link</th>
				<th class="last">Number Merged Results</th>
			</tr>
		</thead>
		<tbody>
	<c:choose>
		<c:when test="${ empty findingList }">
			<tr class="bodyRow">
				<td colspan="6" style="text-align: center;"> No Findings were mapped to vulnerabilities.</td>
			</tr>
		</c:when>
		<c:otherwise>
		<c:forEach var="finding" items="${ findingList }">
			<tr class="bodyRow">
				<td>
					<c:out value="${ finding.channelSeverity.name }"/>
				</td>
				<td>
					<spring:url value="{scanId}/findings/{findingId}" var="findingUrl">
					<spring:param name="scanId" value="${ scan.id }" />
						<spring:param name="findingId" value="${ finding.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(findingUrl) }">
					    <c:out value="${ finding.channelVulnerability.name }"/>
					</a>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.path }"/>
				</td>
				<td>
					<c:out value="${ finding.surfaceLocation.parameter }"/>
				</td>
				<td>
					<spring:url value="../vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				    	<spring:param name="vulnerabilityId" value="${ finding.vulnerability.id }" />
			    	</spring:url>
			    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
						<c:out value="${ finding.vulnerability.id }"/>
					</a>
				</td>
				<td>
					<c:out value="${ finding.numberMergedResults }"/>
				</td>
			</tr>
		</c:forEach>
		</c:otherwise>
	</c:choose>
		</tbody>
	</table>