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
	
	<table class="table sortable table-hover tf-colors" id="anyid">
		<thead>
			<tr>
				<c:if test="${ canModifyVulnerabilities }">
					<th style="width:22px" class="first unsortable"><input type="checkbox" id="chkSelectAll" onclick="ToggleCheckboxes('anyid',0)"></th>
				</c:if>			    
				<th style="width:8px;"></th>
				<th class="pointer" style="min-width:70px" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 2, '<c:out value="${ loginUrl }"/>')">
					Severity<span id="headerCaret2" class="caret-down"></span>
				</th>
				<th class="pointer" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 1, '<c:out value="${ loginUrl }"/>')">
					Type<span id="headerCaret1" class="caret-down"></span>
				</th>
				<th class="pointer" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 3, '<c:out value="${ loginUrl }"/>')">
					Path<span id="headerCaret3" class="caret-down"></span>
				</th>
				<th class="pointer" style="min-width:90px;" onclick="javascript:refillElementSort('#toReplace', '${tableUrl}', 1, 4, '<c:out value="${ loginUrl }"/>')">
					Parameter<span id="headerCaret4" class="caret-down"></span>
				</th>
				<c:if test="${ not empty application.defectTracker }">
					<th>Defect</th>
				</c:if>
				<th style="width:65px;"></th>
			</tr>
		</thead>
		<tbody>
		<c:if test="${ empty vulnerabilityGroups }">
			<tr class="bodyRow">
				<c:if test="${ canModifyVulnerabilities }">
					<td colspan="6" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
				<c:if test="${ not canModifyVulnerabilities }">
					<td colspan="5" style="text-align:center;">No vulnerabilities found.</td>
				</c:if>
			</tr>
		</c:if>
		
		<c:set var="index" value="0"/>
		
		<c:forEach var="vulnGroup" items="${ vulnerabilityGroups }">
			<c:set var="rowClass" value="${ vulnGroup.name }" />
			<c:if test="${ vulnGroup.showHeader }">
				<c:set var="hideClass" value="defaultHide" />
			</c:if>
			<c:if test="${ not vulnGroup.showHeader }">
				<c:set var="hideClass" value="defaultShow"/>
			</c:if>
		
			<c:if test="${ vulnGroup.showHeader && fn:length(vulnGroup.vulnerabilities) != 0 }">
				<tr class="pointer ${ vulnGroup.colorClass }"
						data-caret="caret${ vulnGroup.name }"
						data-toggle-class="${ rowClass }"
						data-expanded="0">
					<c:if test="${ canModifyVulnerabilities }">
						<td>
							<input type="checkbox" class="categoryCheckbox" data-target-class="<c:out value="${ vulnGroup.name }"/>">
						</td>
					</c:if>
					<td class="vulnSectionHeader">
						<span id="caret${ vulnGroup.name }" class="caret-right"></span>
					</td>
					<td class="vulnSectionHeader">
						<c:out value="${ vulnGroup.name }"/>
						(<c:out value="${ fn:length(vulnGroup.vulnerabilities) }"/>) 
					</td>
					<td class="vulnSectionHeader" colspan="4"></td>
					<c:if test="${ not empty application.defectTracker }">
						<td class="vulnSectionHeader"></td>
					</c:if>
				</tr>
			</c:if>
		
			<c:forEach var="vulnerability" items="${vulnGroup.vulnerabilities}">
				<c:set var="index" value="${ index + 1 }"/>
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
				<tr class="bodyRow pointer <c:out value="${ color }"/> ${ rowClass } ${ hideClass }" data-target-div="vulnInfoDiv${vulnerability.id}"
						data-caret-div="caret${vulnerability.id }">
					<c:if test="${ canModifyVulnerabilities }">
						<td>
							<input class="vulnIdCheckbox <c:out value="${ vulnGroup.name }"/>" id="vulnerabilityIds${ index }" type="checkbox" value="${ vulnerability.id }" name="vulnerabilityIds">
							<input class="vulnIdCheckboxHidden" type="hidden" value="on" name="_vulnerabilityIds">
						</td>
					</c:if>
					<td class="expandableTrigger">
						<span id="caret${vulnerability.id }" class="caret-right"></span>
					</td>
					<td class="expandableTrigger" id="severity${ index }"><c:out value="${ vulnerability.genericSeverity.name }"/></td>
					<td class="expandableTrigger">
						<c:out value="${ vulnerability.genericVulnerability.name }"/>
					</td>
					<td class="expandableTrigger" id="path${ index }"><c:out value="${ vulnerability.surfaceLocation.path }"/></td>
					<td class="expandableTrigger" id="parameter${ index }"><c:out value="${ vulnerability.surfaceLocation.parameter }"/></td>
					<c:if test="${ not empty application.defectTracker }">
						<td >
							<div  class="tooltip-container" data-placement="left" title="<c:out value="${ vulnerability.defect.nativeId }"/>" style="width:100%;text-align:center;">
							<c:if test="${ not empty vulnerability.defect }">
								<a id="bugLink${ index }"
										target="_blank" 
										href="<c:out value="${ vulnerability.defect.defectURL }"/>">
									<img src="<%=request.getContextPath()%>/images/icn_bug.png" class="transparent_png" alt="Threadfix" />
								</a>
							</c:if>
							</div>
						</td>
					</c:if>
					<td>
						<spring:url value="{appId}/vulnerabilities/{vulnerabilityId}" var="vulnerabilityUrl">
					        <spring:param name="appId" value="${ application.id }" />
						    <spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
					    </spring:url>
					    <a id="vulnName${index}" href="${ fn:escapeXml(vulnerabilityUrl) }">
							View More
						</a>
					</td>
				</tr>
				<tr class="bodyRow <c:out value="${ color }"/> expandable ${ rowClass } ${ hideClass }">
					<c:set var="numColumns" value="7"/>
					<c:if test="${ not empty application.defectTracker }">
						<c:set var="numColumns" value="8"/>
					</c:if>
					<td colspan="<c:out value="${ numColumns }"/>">
						<div id="vulnInfoDiv${vulnerability.id}" class="collapse">
							<div class="left-tile">
								<c:if test="${not empty vulnerability.findings}">
									<h4>Scan History</h4>
									<div class="report-image" style="width:422px;margin-bottom:20px;background-color:#FFF;padding:0px;">
										<table class="table" style="margin-bottom:0px;">
											<thead class="table">
												<tr class="left-align">
													<th class="first">Channel</th>
													<th>Scan Date</th>
													<th class="last">User</th>
												</tr>
											</thead>
											<tbody>
												<c:forEach var="finding" items="${ vulnerability.findings }" varStatus="status">
													<tr class="left-align bodyRow">
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
									</div>
								</c:if>
							</div>
							
							<div class="right-tile">
								<h4>Comments</h4>
								<div class="report-image" id="commentDiv${ vulnerability.id }" style="width:450px;margin-bottom:10px;">
									<%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>							
								</div>
								<br>
								<%@include file="/WEB-INF/views/applications/modals/vulnCommentModal.jsp"%>
							</div>
						</div>
					</td>
				</tr>
			</c:forEach>
		
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