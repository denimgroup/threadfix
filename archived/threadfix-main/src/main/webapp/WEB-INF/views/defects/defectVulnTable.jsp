<%@ include file="/common/taglibs.jsp"%>

<body>
	<spring:url value="/login.jsp" var="loginUrl"/>
	<spring:url value="defectTable" var="tableUrl">
	</spring:url>
	<c:if test="${ numVulns > 100 }">
	<div ng-non-bindable style="padding-bottom:8px">
		<c:if test="${ page > 4 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', 1, '<c:out value="${ loginUrl }"/>')">First</a>
		</c:if>
	
		<c:if test="${ page >= 4 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 3 }"/></a>
		</c:if>
	
		<c:if test="${ page >= 3 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 2 }"/></a>
		</c:if>
		
		<c:if test="${ page >= 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 1 }"/></a>
		</c:if>
				
		<c:out value="${ page }"/>
	
		<c:if test="${ page <= numPages }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 1 }"/></a>
		</c:if>
		
		<c:if test="${ page <= numPages - 1 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 2 }"/></a>
		</c:if>
		
		<c:if test="${ page <= numPages - 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 3 }"/></a>
		</c:if>
		
		<c:if test="${ page < numPages - 2 }">
			<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ numPages + 1 }, '<c:out value="${ loginUrl }"/>')">Last (<c:out value="${ numPages + 1}"/>)</a>
		</c:if>
		
		<input class="refillElementOnEnter" type="text" id="pageInput" />
		<a href="javascript:refillElementDropDownPage('#toReplace', '${ tableUrl }', '<c:out value="${ loginUrl }"/>')">Go to page</a>
	</div>
	</c:if>
	
	<table ng-non-bindable class="table table-striped sortable" id="anyid">
		<thead>
			<tr>
			    <th class="first"onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1, '<c:out value="${ loginUrl }"/>')">Vulnerability Name</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 2, '<c:out value="${ loginUrl }"/>')">Severity</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 3, '<c:out value="${ loginUrl }"/>')">Path</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 4, '<c:out value="${ loginUrl }"/>')">Parameter</th>
				<th>Defect</th>
				<th>Defect Status</th>
				<th>WAF Rule</th>
				<th class="last unsortable">Select All <input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',7)"></th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty vulnerabilities }">
			<tr class="bodyRow">
				<td colspan="10" style="text-align:center;">No vulnerabilities found.</td>
			</tr>
		</c:if>
		<c:forEach var="vuln" items="${vulnerabilities}" varStatus="vulnStatus">
			<tr class="bodyRow">
				<td>
					<spring:url value="vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vuln.id }" />
				    </spring:url>
				    <a id="vulnName${vulnStatus.count}" href="${ fn:escapeXml(vulnerabilityUrl) }"><c:out value="${ vuln.genericVulnerability.name }"/></a>
				</td>
				<td id="severity${ vulnStatus.count }"><c:out value="${ vuln.genericSeverity.displayName }"/></td>
				<td id="path${ vulnStatus.count }"><c:out value="${ vuln.surfaceLocation.path }"/></td>
				<td id="parameter${ vulnStatus.count }"><c:out value="${ vuln.surfaceLocation.parameter }"/></td>
				<td>
				<c:if test="${ not empty vuln.defect }">
					<spring:url value="vulnerabilities/{vulnerabilityId}/defect" var="defectUrl">
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
					<input id="vulnerabilityIds${ vulnStatus.count }" type="checkbox" value="${ vuln.id }" name="vulnerabilityIds">
					<input type="hidden" value="on" name="_vulnerabilityIds">
				</td>
			</tr>
		</c:forEach>
		</tbody>
	</table>
	
	<script>
        $('.disableSubmitOnEnter').keypress(function(e){
            if ( e.which == 13 ) return false;
        });
        $('.refillElementOnEnter').keypress(function(e) {
            if (e.which == 13) {
                refillElementDropDownPage('#toReplace', '<c:out value="${ tableUrl }"/>', '<c:out value="${ loginUrl }"/>');
                return false;
            }
        });
	</script>
</body>