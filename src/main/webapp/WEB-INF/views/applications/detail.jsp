<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vuln-comments.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/ajax_replace.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/authentication.js"></script>
	<script type="text/javascript">
	window.onload = function()
    {
		$('#vulnTab').button('toggle');
		toggleFilters(false, null, null);//refillElement('#toReplace', '${ application.id }/table', 1);
    };
    </script>
	<script>
	
	</script>
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
	
	<ul class="breadcrumb">
	    <li><a href="<spring:url value="/"/>">Teams</a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
	    <li class="active"><c:out value="${ application.name }"/></li>
    </ul>
	
	<h2 style="padding-bottom:5px;">Application: <span id="nameText"><c:out value="${ application.name }"/></span>
	<c:if test="${ canManageApplications }">
		<span style="font-size:60%;padding-left:10px;">
			<a id="editLink" href="${ fn:escapeXml(editUrl) }">Edit</a> | 
			<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete the application?')">Delete</a>
		</span>
	</c:if>
	</h2>
	
	<c:if test="${ not empty message }">
		<center class="errors" ><c:out value="${ message }"/> <a id="refreshLink" href="<spring:url value=""/>">Refresh the page.</a></center>
	</c:if>
	
	<c:if test="${ not empty error }">
		<center class="errors" ><c:out value="${ error }"/></center>
	</c:if>
	
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
	
	<a id="showDetailsLink" ${ status.count }"  class="btn" href="#" data-toggle="collapse" data-target="#appInfoDiv">Show Details</a>
	<c:if test="${ canUploadScans }">
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
			<li class="active">
				<a data-toggle="tab" id="vulnTabLink" onclick="javascript:switchTabs('<c:out value="${vulnTabUrl }"/>');return false;">Vulnerabilities</a>
			</li>
			<li>
				<a data-toggle="tab" id="scanTabLink" onclick="javascript:switchTabs('<c:out value="${scanTabUrl }"/>');return false;">Scans</a>
			</li>
			<li>
				<a data-toggle="tab" id="closedVulnTabLink" onclick="javascript:switchTabs('<c:out value="${closedTabUrl }"/>');return false;">Closed Vulnerabilities</a>
			</li>
			<li>
				<a data-toggle="tab" id="falsePositiveTabLink" onclick="javascript:switchTabs('<c:out value="${falsePositiveTabUrl }"/>');return false;">False Positives</a>
			</li>
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
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">Add Defect Tracker</h4>
		</div>
		<div id="addDTFormDiv">
			<%@ include file="/WEB-INF/views/applications/forms/addDTForm.jsp" %>
		</div>
	</div>
	
	<%@ include file="/WEB-INF/views/config/defecttrackers/modals/createDTModal.jsp" %>
	
	<%@ include file="/WEB-INF/views/defects/submitDefectModal.jsp" %>
	
</body>