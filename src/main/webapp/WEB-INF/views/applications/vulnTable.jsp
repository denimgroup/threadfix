<%@ include file="/common/taglibs.jsp"%>

<body>
	<spring:url value="{appId}/table" var="tableUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<c:if test="${ numVulns > 100 }">
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
		
		<input class="refillElementOnEnter" type="text" id="pageInput" />
		<a href="javascript:refillElementDropDownPage('#toReplace', '${ tableUrl }')">Go to page</a>
	</div>
	</c:if>
	
	<table class="formattedTable sortable filteredTable" id="anyid">
		<thead>
			<tr>
				<th class="first">If Merged</th>
			    <th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1)">Vulnerability Name</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 2)">Severity</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 3)">Path</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 4)">Parameter</th>
				<th>Age (days)</th>
				<th>Defect</th>
				<th>Defect Status</th>
				<th>WAF Rule</th>
				<c:if test="${ not canModifyVulnerabilities }">
					<th class="unsortable last">WAF Events</th>
				</c:if>
				<c:if test="${ canModifyVulnerabilities }">
					<th class="unsortable">WAF Events</th>
					<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',10)"></th>
				</c:if>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty vulnerabilities }">
			<tr class="bodyRow">
				<c:if test="${ canModifyVulnerabilities }">
					<td colspan="11" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
				<c:if test="${ not canModifyVulnerabilities }">
					<td colspan="10" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
			</tr>
		</c:if>
		<c:forEach var="vuln" items="${vulnerabilities}" varStatus="vulnStatus">
			<tr class="bodyRow">
				<td>
					<c:if test="${ fn:length(vuln.findings) > 1 }">
						<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        	<spring:param name="appId" value="${ application.id }" />
					    	<spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    	</spring:url>
				    	<a href="${ fn:escapeXml(vulnerabilityUrl) }">
				        	<c:out value="${ fn:length(vuln.findings) }"/>
				    	</a>
					</c:if>
				</td>
				<td>
					<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
				    <a id="vulnName${vulnStatus.count}" href="${ fn:escapeXml(vulnerabilityUrl) }"><c:out value="${ vuln.genericVulnerability.name }"/></a>
				</td>
				<td id="severity${ vulnStatus.count }"><c:out value="${ vuln.genericSeverity.name }"/></td>
				<td id="path${ vulnStatus.count }"><c:out value="${ vuln.surfaceLocation.path }"/></td>
				<td id="parameter${ vulnStatus.count }"><c:out value="${ vuln.surfaceLocation.parameter }"/></td>
				<td><c:out value="${ ages[vulnStatus.count - 1] }"/></td>
				<td>
				<c:if test="${ not empty vuln.defect }">
					<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}/defect" var="defectUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
					<a href="${ fn:escapeXml(defectUrl) }">
				        <c:out value="${ vuln.defect.nativeId }" />
				    </a>
				</c:if>
				</td>
				<td>
				<c:choose>
					<c:when test="${ not empty vuln.defect }">
						<c:out value="${ vuln.defect.status }"/>
					</c:when>
					<c:otherwise>
						No Defect
					</c:otherwise>
				</c:choose>
				</td>
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
				<c:if test="${ canModifyVulnerabilities }">
					<td>
						<input id="vulnerabilityIds${ vulnStatus.count }" type="checkbox" value="${ vuln.id }" name="vulnerabilityIds">
						<input type="hidden" value="on" name="_vulnerabilityIds">
					</td>
				</c:if>
			</tr>
		</c:forEach>
		</tbody>
		<c:if test="${ canModifyVulnerabilities }">
		<tfoot>
			<tr class="footer">
				<td colspan="11" style="text-align:right">
					<input type="submit" value="Mark Selected as False Positives">
				</td>
			</tr>
		</tfoot>
		</c:if>
	</table>
	
	<script>
	$('.disableSubmitOnEnter').keypress(function(e){
	    if ( e.which == 13 ) return false;
	});
	$('.refillElementOnEnter').keypress(function(e) {
		if (e.which == 13) {
			refillElementDropDownPage('#toReplace', '<c:out value="${ tableUrl }"/>');
			return false;
		}
	});
	</script>
</body>