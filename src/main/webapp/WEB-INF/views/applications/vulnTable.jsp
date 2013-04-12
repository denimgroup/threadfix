<%@ include file="/common/taglibs.jsp"%>

<body>

	<div id="errorDiv"></div>

	<spring:url value="/login.jsp" var="loginUrl"/>
	<span id="ajaxVulnTable"></span>
	<spring:url value="{appId}/table" var="tableUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<c:if test="${ numVulns > 100 }">
	<div class="pagination">
		<ul style="vertical-align:middle">
		<c:if test="${ page > 4 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', 1, '<c:out value="${ loginUrl }"/>')">First</a>
			</li>
		</c:if>
	
		<c:if test="${ page >= 4 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 3 }"/></a>
			</li>
		</c:if>
	
		<c:if test="${ page >= 3 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 2 }"/></a>
			</li>
		</c:if>
		
		<c:if test="${ page >= 2 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page - 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page - 1 }"/></a>
			</li>
		</c:if>
		
		<li class="active"><a href="#"><c:out value="${ page }"/></a></li>
	
		<c:if test="${ page <= numPages }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 1 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 1 }"/></a>
			</li>
		</c:if>
		
		<c:if test="${ page <= numPages - 1 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 2 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 2 }"/></a>
			</li>
		</c:if>
		
		<c:if test="${ page <= numPages - 2 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ page + 3 }, '<c:out value="${ loginUrl }"/>')"><c:out value="${ page + 3 }"/></a>
			</li>
		</c:if>
		
		<c:if test="${ page < numPages - 2 }">
			<li>
				<a href="javascript:refillElement('#toReplace', '${tableUrl}', ${ numPages + 1 }, '<c:out value="${ loginUrl }"/>')">Last (<c:out value="${ numPages + 1}"/>)</a>
			</li>
		</c:if>
		</ul>
	
	
		<input class="refillElementOnEnter" type="text" id="pageInput" />
		<a href="javascript:refillElementDropDownPage('#toReplace', '${ tableUrl }', '<c:out value="${ loginUrl }"/>')">Go to page</a>
	</div>
	
	</c:if>
	
	<table class="table table-striped sortable table-hover" id="anyid">
		<thead>
			<tr>
				<c:if test="${ canModifyVulnerabilities }">
					<th class="first unsortable"><input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',0)"></th>
				</c:if>			    
				<th style="width:8px;"></th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1, '<c:out value="${ loginUrl }"/>')">
					Type<span id="headerCaret1" class="caret-down"></span>
				</th>
				<th style="min-width:70px" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 2, '<c:out value="${ loginUrl }"/>')">
					Severity<span id="headerCaret2" class="caret-down"></span>
				</th>
				<th onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 3, '<c:out value="${ loginUrl }"/>')">
					Path<span id="headerCaret3" class="caret-down"></span>
				</th>
				<th style="min-width:90px;" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 4, '<c:out value="${ loginUrl }"/>')">
					Parameter<span id="headerCaret4" class="caret-down"></span>
				</th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty vulnerabilities }">
			<tr class="bodyRow">
				<c:if test="${ canModifyVulnerabilities }">
					<td colspan="6" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
				<c:if test="${ not canModifyVulnerabilities }">
					<td colspan="5" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
			</tr>
		</c:if>
		<c:forEach var="vulnerability" items="${vulnerabilities}" varStatus="vulnStatus">
			<c:if test="${ vulnerability.genericSeverity.name == 'Critical' }">
			      <c:set var="color" value="error" />
			</c:if>
			<c:if test="${ vulnerability.genericSeverity.name == 'High' }">
			      <c:set var="color" value="warning" />
			</c:if>
			<c:if test="${ vulnerability.genericSeverity.name == 'Medium' }">
			      <c:set var="color" value="success" />
			</c:if>
			<c:if test="${ vulnerability.genericSeverity.name == 'Low' }">
			      <c:set var="color" value="info" />
			</c:if>
			<c:if test="${ vulnerability.genericSeverity.name == 'Info' }">
			      <c:set var="color" value="info" />
			</c:if>
			<tr class="bodyRow <c:out value="${ color }"/>">
				<c:if test="${ canModifyVulnerabilities }">
					<td>
						<input class="vulnIdCheckbox" id="vulnerabilityIds${ vulnStatus.count }" type="checkbox" value="${ vulnerability.id }" name="vulnerabilityIds">
						<input class="vulnIdCheckboxHidden" type="hidden" value="on" name="_vulnerabilityIds">
					</td>
				</c:if>
				<td onclick="javascript:toggleExpandable('#vulnInfoDiv${vulnerability.id}', '#caret${vulnerability.id }')">
					<span id="caret${vulnerability.id }" class="caret-right"></span>
				</td>
				<td>
					<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
				        <spring:param name="appId" value="${ application.id }" />
					    <spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
				    </spring:url>
				    <a id="vulnName${vulnStatus.count}" href="${ fn:escapeXml(vulnerabilityUrl) }"><c:out value="${ vulnerability.genericVulnerability.name }"/></a>
				</td>
				<td id="severity${ vulnStatus.count }"><c:out value="${ vulnerability.genericSeverity.name }"/></td>
				<td id="path${ vulnStatus.count }"><c:out value="${ vulnerability.surfaceLocation.path }"/></td>
				<td id="parameter${ vulnStatus.count }"><c:out value="${ vulnerability.surfaceLocation.parameter }"/></td>
			</tr>
			<tr class="bodyRow <c:out value="${ color }"/> expandable">
				<td colspan="7">
					<div id="vulnInfoDiv${vulnerability.id}" class="collapse">
						<div class="left-tile">
							<c:if test="${not empty vulnerability.findings}">
								<h4>Scan History</h4>
								<table class="table">
									<thead class="table">
										<tr class="left-align <c:out value="${ color }"/>">
											<th class="first">Channel</th>
											<th>Scan Date</th>
											<th class="last">User</th>
										</tr>
									</thead>
									<tbody>
										<c:forEach var="finding" items="${ vulnerability.findings }" varStatus="status">
											<tr class="left-align bodyRow <c:out value="${ color }"/>">
												<td id="scan${ status.count }ChannelType"><c:out
														value="${ finding.scan.applicationChannel.channelType.name }" /></td>
												<td id="scan${ status.count }ImportTime"><fmt:formatDate value="${ finding.scan.importTime.time }"
														type="both" dateStyle="short" timeStyle="medium" /></td>
												<td id="scan${ status.count }ChannelType${ status.count }"><c:if test="${ not empty finding.scan.user }">
														<!-- Got info from scan, the normal case -->
														<c:out value="${ finding.scan.user.name}" />
													</c:if> <c:if
														test="${ empty finding.scan.user and not empty finding.user }">
														<!-- Got info from finding, probably a manual scan -->
														<c:out value="${ finding.user.name}" />
													</c:if> <c:if test="${ empty finding.scan.user and empty finding.user }">
												No user found. Probably a remote scan.
											</c:if></td>
											</tr>
										</c:forEach>
									</tbody>
								</table>
							</c:if>
						</div>
						<div class="right-tile" id="commentDiv${ vulnerability.id }">
							<%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>							
						</div>
					</div>
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