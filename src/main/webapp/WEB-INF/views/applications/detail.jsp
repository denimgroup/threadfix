<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/authentication.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_search.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/radio_select.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/application_page.js"></script>
</head>

<body id="apps">
	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ application.organization.id }"/>
	</spring:url>
	<spring:url value="{appId}/edit" var="editUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	<spring:url value="{appId}/delete" var="deleteUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<div id="headerDiv">
		<%@ include file="/WEB-INF/views/applications/detailHeader.jsp" %>
	</div>
	
	<div style="padding-top:10px;" id="helpText">
		Applications are used to store, unify, and manipulate scan results from security scanners.
		<c:if test="${ empty application.scans }">
			<br/><br/>To get started, click Upload Scan to start uploading security scans.
		</c:if>
	</div>
	
	<div id="appInfoDiv" class="collapse">
		<table class="dataTable" style="margin-bottom:18px">
			<tbody>
				<c:if test="${ not empty application.url }">
					<tr>
						<td>URL</td>
						<td class="inputValue">
							<a id="urlText" href="<spring:url value="${ fn:escapeXml(application.url) }" />"><c:out value="${ application.url }" /></a>
						</td>
					</tr>
				</c:if>
				<tr id="appDTDiv">
					<%@ include file="/WEB-INF/views/applications/defectTrackerRow.jsp" %>
				</tr>
				<tr id="appWafDiv">
					<%@ include file="/WEB-INF/views/applications/wafRow.jsp" %>
				</tr>
				<tr>
					<td>Criticality</td>
					<td class="inputValue"><c:out value="${ application.applicationCriticality.name }"/></td>
				</tr>
			</tbody>
		</table>
	</div>
	
	<c:if test="${ canUploadScans }">
		<a id="uploadScanModalLink" href="#uploadScan${ application.id }" role="button" class="btn" data-toggle="modal">Upload Scan</a>
		<%@ include file="/WEB-INF/views/applications/modals/uploadScanModal.jsp" %>
		<%@ include file="/WEB-INF/views/applications/modals/manualFindingModal.jsp" %>
	</c:if>
	
	<c:if test="${ not empty application.scans }"> 
	
		<spring:url value="/organizations/{orgId}/applications/{appId}/vulnTab" var="vulnTabUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<spring:url value="/organizations/{orgId}/applications/{appId}/scanTab" var="scanTabUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<spring:url value="/organizations/{orgId}/applications/{appId}/closedTab" var="closedTabUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<spring:url value="/organizations/{orgId}/applications/{appId}/falsePositiveTab" var="falsePositiveTabUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<br>
	
		<ul class="nav nav-tabs margin-top">
			<li class="active pointer">
				<a data-toggle="tab" id="vulnTabLink" onclick="javascript:switchTabs('<c:out value="${vulnTabUrl }"/>');return false;">
					${ fn:escapeXml(numVulns) } 
					<c:if test="${ numVulns == 1 }">Vulnerability</c:if>
					<c:if test="${ numVulns != 1 }">Vulnerabilities</c:if>
				</a>
			</li>
			<li class="pointer">
				<a data-toggle="tab" id="scanTabLink" onclick="javascript:switchTabs('<c:out value="${scanTabUrl }"/>');return false;">
					${ fn:length(application.scans) }
					<c:if test="${ fn:length(application.scans) == 1 }">Scan</c:if>
					<c:if test="${ fn:length(application.scans) != 1 }">Scans</c:if>
				</a>
			</li>
			<c:if test="${ numClosedVulns != 0 }">
				<li class="pointer">
					<a data-toggle="tab" id="closedVulnTabLink" onclick="javascript:switchTabs('<c:out value="${closedTabUrl }"/>');return false;">
						${fn:escapeXml(numClosedVulns) } Closed 
						<c:if test="${fn:escapeXml(numClosedVulns) == 1}"> Vulnerability</c:if>
						<c:if test="${fn:escapeXml(numClosedVulns) != 1}"> Vulnerabilities</c:if>
					</a>
				</li>
			</c:if>
			<c:if test="${ falsePositiveCount != 0 }">
				<li class="pointer">
					<a data-toggle="tab" id="falsePositiveTabLink" onclick="javascript:switchTabs('<c:out value="${falsePositiveTabUrl }"/>');return false;">
						${fn:escapeXml(falsePositiveCount) } False 
						<c:if test="${fn:escapeXml(falsePositiveCount) == 1}">Positive</c:if>
						<c:if test="${fn:escapeXml(falsePositiveCount) != 1}">Positives</c:if>
					</a>
				</li>
			</c:if>
		</ul>
		
	    <div id="tabsDiv">
			<%@ include file="/WEB-INF/views/applications/tabs/vulnTab.jsp" %>
		</div>
	
	</c:if>
	
	<div id="addWaf" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/applications/forms/addWafForm.jsp" %>
	</div>
	
	<div id="createWaf" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
	</div>
	
	<div id="addDefectTracker" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" style="width:600px;">
		<div class="modal-header">
			<h4 id="myModalLabel">Add Defect Tracker</h4>
		</div>
		<div id="addDTFormDiv">
			<%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>
		</div>
	</div>
	
	<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %> 
	
	<c:if test="${ not empty application.defectTracker }">
		<%@ include file="/WEB-INF/views/defects/submitDefectModal.jsp" %>
	</c:if>
	
</body>