<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ application.name }"/></title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/confirm.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/authentication.js"></script>
	<script type="text/javascript">
	window.onload = function()
    {
		toggleFilters(false, null, null);//refillElement('#toReplace', '${ application.id }/table', 1);
    };
    </script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/bootstrap.min.js" media="screen"></script>
	<script>
	function submitAjaxModal(url, formId, formDiv, successDiv, modalName, collapsible) {
		$.ajax({
			type : "POST",
			url : url,
			data : $(formId).serializeArray(),
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$(formDiv).html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					$(modalName).on('hidden', function () {
						$(successDiv).html(text);
						$(collapsible).collapse('show');
				    });
				    $(modalName).modal('hide');
				} else {
					try {
						var json = JSON.parse(text);
						alert(json.error);
					} catch (e) {
						history.go(0);
					}
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				history.go(0);
		    }
		});
	}
	function switchDTModals() {
	    $("#addDefectTracker").modal('hide');
	    $("#createDefectTracker").modal('show');
	    return false;
	};
	function switchWafModals() {
	    $("#addWaf").modal('hide');
	    $("#createWaf").modal('show');
	    return false;
	};
	function addWafAndRefresh(url) {
		$.ajax({
			type : "POST",
			url : url,
			data : $('#addWafForm').serializeArray(),
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$('#addWaf').html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					$('#addWaf').on('hidden', function () {
						$('#appWafDiv').html(text);
				    });
				    $('#addWaf').modal('hide');
				} else {
					try {
						var json = JSON.parse(text);
						alert(json.error);
					} catch (e) {
						history.go(0);
					}
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				history.go(0);
		    }
		});
	    return false;
	}
	function createWafAndRefresh(url) {
		$.ajax({
			type : "POST",
			url : url,
			data : $('#wafForm').serializeArray(),
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$('#createWaf').html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					$('#createWaf').on('hidden', function () {
						$('#addWaf').html(text);
				    });
				    $('#createWaf').modal('hide');
				    $("#addWaf").modal('show');
				} else {
					try {
						var json = JSON.parse(text);
						alert(json.error);
					} catch (e) {
						history.go(0);
					}
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				history.go(0);
		    }
		});
	    return false;
	}
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
	
	<div style="font-size:150%">Team: <a id="organizationText" href="${fn:escapeXml(orgUrl)}"><c:out value="${ application.organization.name }"/></a></div>
	<br>
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

	<table class="dataTable">
		<tbody>
			<c:if test="${ not empty application.url }">
				<tr>
					<td>URL:</td>
					<td class="inputValue">
						<a id="urlText" href="<spring:url value="${ fn:escapeXml(application.url) }" />"><c:out value="${ application.url }" /></a>
					</td>
				</tr>
			</c:if>
			<tr>
				<td>Defect Tracker:</td>
		<c:choose>
			<c:when test="${ empty application.defectTracker }">
				<td class="inputValue">
					<a href="#addDefectTracker" role="button" class="btn" data-toggle="modal">Add Defect Tracker</a>
				</td>
			</c:when>
			<c:otherwise>
				<td class="inputValue">
					<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="defectTrackerUrl">
						<spring:param name="defectTrackerId" value="${ application.defectTracker.id }"/>
					</spring:url>
					<a id="defectTrackerText" href="${ fn:escapeXml(defectTrackerUrl) }"><c:out value="${ application.defectTracker.name }"/></a>
					<em>(<a href="<spring:url value="${ fn:escapeXml(application.defectTracker.url) }" />"><c:out value="${ fn:escapeXml(application.defectTracker.url) }"/></a>)</em>
					<a href="#addDefectTracker" role="button" class="btn" data-toggle="modal">Edit Defect Tracker</a>
				</td>
			</c:otherwise>
		</c:choose>
			</tr>
			<tr>
				<td>WAF:</td>
				<td class="inputValue">
					<div id="appWafDiv">
					<c:choose>
						<c:when test="${ empty application.waf }">
							<a href="#addWaf" role="button" class="btn" data-toggle="modal">Add WAF</a>
						</c:when>
						<c:otherwise>
							<spring:url value="/wafs/{wafId}" var="wafUrl">
								<spring:param name="wafId" value="${ application.waf.id }"/>
							</spring:url>
							<a id="wafText" href="${ fn:escapeXml(wafUrl) }"><c:out value="${ application.waf.name }"/></a>
							<em>(<c:out value="${ application.waf.wafType.name }"/>)</em>
							<a href="#addWaf" role="button" class="btn" data-toggle="modal">Edit WAF</a>
						</c:otherwise>
					</c:choose>
					</div>
				</td>
			</tr>
			<tr>
				<td>Criticality:</td>
				<td class="inputValue"><c:out value="${ application.applicationCriticality.name }"/></td>
			</tr>
		</tbody>
	</table>
	
	<c:if test="${ canUploadScans }">
		<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
			<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a>
			<input id="fileInput" type="file" name="file" size="50" />
			<button class="btn" id="uploadScanButton" type="submit">Upload Scan</button>
		</form:form>
		<span>
			<spring:url value="{appId}/scans/new" var="addFindingUrl">
				<spring:param name="appId" value="${ application.id }"/>
			</spring:url>
			<a id="addFindingManuallyLink" href="${ fn:escapeXml(addFindingUrl) }">Manually Add Vulnerabilities</a>
		</span>
	</c:if>
	
	
	<c:if test="${ not empty application.scans }"> 
	<h3 style="padding-top:10px;">All Open Vulnerabilities</h3>
	
	<p>Listing <span id="totalVulnCount"><c:out value="${ numVulns }"/></span>
		<c:choose>
			<c:when test="${ numVulns == 1 }">
				vulnerability
			</c:when>
			<c:otherwise>
				vulnerabilities
			</c:otherwise>
		</c:choose>
		from 
		<c:choose>
			<c:when test="${ fn:length(application.scans ) == 1 }">
				1 scan.
			</c:when>
			<c:otherwise>
				<c:out value="${ fn:length(application.scans) }"/> scans.
			</c:otherwise>
		</c:choose>
		<spring:url value="{appId}/scans" var="scanUrl">
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
		
		<a id="viewScansLink" href="${ fn:escapeXml(scanUrl) }">View Scans</a>
		<c:if test="${ falsePositiveCount > 0 }">
			<spring:url value="{appId}/falsepositives/unmark" var="unmarkFPUrl">
				<spring:param name="appId" value="${ application.id }"/>
			</spring:url>
			<span style="padding-left:2px;"><a id="unmarkMarkedFalsePositivesLink" href="${ fn:escapeXml(unmarkFPUrl) }">
				<c:if test="${ falsePositiveCount == 1 }">
					View / Unmark 1 False Positive</c:if>
				<c:if test="${ falsePositiveCount > 1 }">
					View / Unmark <c:out value="${ falsePositiveCount }"/> False Positives</c:if>
			</a></span>
		</c:if>
	</p>

	<c:choose>
		<c:when test="${ numClosedVulns != 0}">
			<spring:url value="{appId}/closedVulnerabilities" var="closedVulnUrl">	
				<spring:param name="appId" value="${ application.id }"/>
			</spring:url>	
			<a id="viewClosedVulnsLink" href="${ fn:escapeXml(closedVulnUrl) }">View <c:out value="${ numClosedVulns }"/> closed 
			<c:choose>
			<c:when test="${ numClosedVulns == 1 }">
				Vulnerability.
			</c:when>
			<c:otherwise>
				Vulnerabilities.
			</c:otherwise>
		</c:choose></a>
		</c:when>
	</c:choose>

	<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
       	<spring:param name="appId" value="${ application.id }" />
   	</spring:url>
	<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">
	
	<spring:url value="{appId}/table" var="tableUrl">
		<spring:param name="appId" value="${ application.id }"/>
	</spring:url>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td rowspan="4" style="padding-bottom:10px; vertical-align:top">
					<div class="buttonGroup" id="vulnerabilityFilters">
						<table style="margin:0px;padding:0px;margin-left:auto;">
							<tr>
								<td colspan="2"><b>Vulnerability Name:</b></td>
								<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="descriptionFilterInput" /></td>
							</tr>
							<tr>
								<td colspan="2"><b>CWE ID:</b></td>
								<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="cweFilterInput" /></td>
							</tr>
							<tr>
								<td colspan="2"><b>Severity:</b></td>
								<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="severityFilterInput" /></td>
							</tr>
							<tr>
								<td colspan="2"><b>Location:</b></td>
								<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="locationFilterInput"/></td>
							</tr>
							<tr>
								<td colspan="2"><b>Parameter:</b></td>
								<td style="padding-left:5px; padding-top:3px"><input class="disableSubmitOnEnter" type="text" id="parameterFilterInput" /></td>
							</tr>
							<tr>
								<td><a id="filterLink" href="javascript:filter('#toReplace', '${ tableUrl }');">Filter</a>&nbsp;|&nbsp;</td>
								<td><a id="clearFilterLink" href="javascript:clearFilters('#toReplace', '${ tableUrl }');">Clear Filters</a>&nbsp;|&nbsp;</td>
								<td><a id="hideFilterLink" href="javascript:toggleFilters(false, '#toReplace', '${ tableUrl }');">Hide Filters</a></td>
							</tr>
						</table>
					</div>
					<div id="showFilters" style="display:none;">
						<a id="showFiltersLink" href="javascript:toggleFilters(true, '#toReplace', '${ tableUrl }');">Show Filters</a>
					</div>
					<script>toggleFilters(false, '#toReplace', '${ tableUrl }');</script>
				</td>
			</tr>
		</tbody>
	</table>
    
    <div id="toReplace">
   
		<table class="formattedTable sortable filteredTable" id="anyid">
			<thead>
				<tr>
					<th class="first">If Merged</th>
				    <th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 1, '<c:out value="${ loginUrl }"/>')">Vulnerability Name</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 2, '<c:out value="${ loginUrl }"/>')">Severity</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 3, '<c:out value="${ loginUrl }"/>')">Path</th>
					<th onclick="javascript:refillElementSort('#toReplace', '${ tableUrl }', 1, 4, '<c:out value="${ loginUrl }"/>')">Parameter</th>
					<th>Age</th>
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
				<tr class="bodyRow">
					<c:if test="${ canModifyVulnerabilities }">
						<td colspan="12" style="text-align:center;">Loading Vulnerabilities.</td>
					</c:if>
					
					<c:if test="${ not canModifyVulnerabilities }">
						<td colspan="11" style="text-align:center;">Loading Vulnerabilities.</td>
					</c:if>
				</tr>
			</tbody>
			<c:if test="${ canModifyVulnerabilities }">
				<tfoot>
					<tr class="footer">
						<td colspan="12" style="text-align:right">
							<input type="submit" value="Mark Selected as False Positives">
						</td>
					</tr>
				</tfoot>
			</c:if>
		</table>
	
	</div>
	
	</form:form>

	<table class="dataTable">
		<tbody>
			<tr>
			<c:if test="${ not empty application.defectTracker }">
				<td>Defect Tracker:</td>
				<td class="inputValue">
					<c:if test="${ canSubmitDefects }">
						<spring:url value="{appId}/defects" var="defectsUrl">
					        <spring:param name="appId" value="${ application.id }" />
					    </spring:url>
					    <a href="${ fn:escapeXml(defectsUrl) }">Submit Defects</a> |
				    </c:if>
				    <spring:url value="{appId}/defects/update" var="updateUrl">
				    	<spring:param name="appId" value="${ application.id }"/>
				    </spring:url>
					<a href="${ fn:escapeXml(updateUrl) }">Update Status from <c:out value="${application.defectTracker.defectTrackerType.name }"/></a>
				</td>
			</c:if>
			</tr>
			<c:if test="${ canViewJobStatuses }">
			<tr>
				<td>Jobs:</td>
				<td class="inputValue">
					<a href="<spring:url value="/jobs/open" />">View Open</a> |
					<a href="<spring:url value="/jobs/all" />">View All</a>
				</td>
			</tr>
			</c:if>
		</tbody>
	</table>
	
	</c:if>
	
	<div id="addWaf" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">Add WAF</h4>
		</div>
		<spring:url value="/organizations/{orgId}/applications/{appId}/edit/wafAjax" var="saveUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
			<form:form id="addWafForm" style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
			<div class="modal-body">
				<table>
					<tr>
						<td>WAF</td>
						<td class="inputValue">
							<form:select style="margin:5px;" id="wafSelect" path="waf.id">
								<form:option value="0" label="<none>" />
								<form:options items="${ wafList }" itemValue="id" itemLabel="name"/>
							</form:select>
							<a href="#" class="btn" onclick="switchWafModals()">Create New WAF</a>
						</td>
						<td style="padding-left:5px" colspan="2" >
							<form:errors path="waf.id" cssClass="errors" />
						</td>
					</tr>
				</table>
			</div>
			<div class="modal-footer">
				<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
				<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:addWafAndRefresh('<c:out value="${saveUrl }"/>');return false;">Update Application</a>
			</div>
		</form:form>
	</div>
	
	<div id="createWaf" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">Create New WAF</h4>
		</div>
		<spring:url value="/wafs/new/ajax" var="saveUrl"/>
		<form:form id="wafForm" style="margin-bottom:0px;" modelAttribute="waf" method="post" action="${ fn:escapeXml(saveUrl) }">
			<div class="modal-body">
				<table class="dataTable">
					<tbody>
					    <tr>
							<td>Name</td>
							<td class="inputValue">
								<form:input style="margin:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
							</td>
							<td style="padding-left: 5px">
								<form:errors path="name" cssClass="errors" />
							</td>
						</tr>
						<tr>
							<td>Type</td>
							<td class="inputValue">
								<form:select style="margin:5px;" id="typeSelect" path="wafType.id">
									<form:options items="${ wafTypeList }" itemValue="id" itemLabel="name" />
								</form:select>
							</td>
							<td style="padding-left: 5px">
								<form:errors path="wafType.id" cssClass="errors" />
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<div class="modal-footer">
				<input type="hidden" name="applicationId" value="<c:out value="${ application.id }"/>">
				<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
				<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:createWafAndRefresh('<c:out value="${saveUrl }"/>');return false;">Create WAF</a>
			</div>
		</form:form>
	</div>
	
	<div id="addDefectTracker" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" style="width:600px;">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">Add Defect Tracker</h4>
		</div>
		<spring:url value="/organizations/{orgId}/applications/{appId}/edit" var="saveUrl">
			<spring:param name="orgId" value="${ application.organization.id }"/>
			<spring:param name="appId" value="${ application.id }"/>
		</spring:url>
			<form:form style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
			<div class="modal-body">
				<table>
					<tr>
						<td>Defect Tracker</td>
						<td class="inputValue">
							<c:if test="${ not empty defectTrackerList }">
								<form:select style="margin:5px;" id="defectTrackerId" path="defectTracker.id">
									<form:option value="0" label="<none>"/>
									<form:options items="${defectTrackerList}" itemValue="id" itemLabel="displayName"/>
								</form:select>
								<c:if test="${ canManageDefectTrackers }">
									<a style="padding-left:10px;" id="configureDefectTrackersLink" href="<spring:url value="/configuration/defecttrackers/new"/>">Create a Defect Tracker</a>
								</c:if>
							</c:if>
							<a href="#" class="btn" onclick="switchDTModals()">Create New Defect Tracker</a>
						</td>
						<td style="padding-left:5px" colspan="2" >
							<form:errors path="defectTracker.id" cssClass="errors" />
						</td>
					</tr>
					<tr class="defecttracker_row">
						<td>Username</td>
						<td class="inputValue">
							<form:input style="margin:5px;" id="username" path="userName" size="50" maxlength="50"/>
						</td>
						<td style="padding-left:5px" colspan="2" >
							<form:errors path="userName" cssClass="errors" />
						</td>
					</tr>
					<tr class="defecttracker_row">
						<td>Password</td>
						<td class="inputValue">						
							<form:password style="margin:5px;" id="password" showPassword="true" path="password" size="50" maxlength="50" />
						</td>
						<td style="padding-left:5px" colspan="2" >
							<form:errors path="password" cssClass="errors" />
						</td>
					</tr>
					<tr>
						<td>
						<spring:url value="/organizations/{orgId}/applications/jsontest" var="testUrl">
							<spring:param name="orgId" value="${ application.organization.id }" />
							</spring:url>
						<a href="javascript:jsonTest('${ fn:escapeXml(testUrl) }');" id="jsonLink">Test Connection</a>
						</td>
						<td>
						<div id="toReplaceDT">
						</div>
						</td>
					</tr>
					<tr class="defecttracker_row">
						<td id="projectname">Product Name</td>
						<td class="inputValue">
							<form:select style="margin:5px;" id="projectList" path="projectName">
								<c:if test="${ not empty application.projectName }">
									<option value="${ application.projectName }"><c:out value="${ application.projectName }"/></option>
								</c:if>
							</form:select>
						</td>
						<td style="padding-left:5px" colspan="2" >
							<form:errors path="projectName" cssClass="errors" />
						</td>
					</tr>
				</table>
			</div>
			<div class="modal-footer">
				<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
				<button type="submit" class="btn btn-primary">Update Application</button>
			</div>
		</form:form>
	</div>
	
	<spring:url value="/configuration/defecttrackers/new" var="newDTUrl"/>
	<div id="createDefectTracker" class="modal hide fade" tabindex="-1"
		role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<div class="modal-header">
			<button type="button" class="close" data-dismiss="modal"
				aria-hidden="true">X</button>
			<h4 id="myModalLabel">New Defect Tracker</h4>
		</div>
		<spring:url value="/configuration/defecttrackers/new" var="saveUrl"/>
		<form:form style="margin-bottom:0px;" modelAttribute="defectTracker" method="post" action="${ fn:escapeXml(saveUrl) }">
			<div class="modal-body">
				<table class="dataTable">
					<tbody>
					    <tr>
							<td>Name:</td>
							<td class="inputValue">
								<form:input style="margin:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
							</td>
							<td style="padding-left: 5px">
								<form:errors path="name" cssClass="errors" />
							</td>
						</tr>
						<tr>
							<td>URL:</td>
							<td class="inputValue">
								<c:if test="${ not empty defectTracker.url }">
									<script>
										var initialUrl = '<c:out value="${ defectTracker.url }"/>';
									</script>
								</c:if>
								<form:input style="margin:5px;" id="urlInput" path="url" cssClass="focus" size="50" maxlength="255"/>
							</td>
							<td style="padding-left: 5px">
								<form:errors path="url" cssClass="errors" />
								<c:if test="${ showKeytoolLink }">
									<span class="errors">Instructions for importing a self-signed certificate can be found</span> <a target="_blank" href="http://code.google.com/p/threadfix/wiki/ImportingSelfSignedCertificates">here</a>.
								</c:if>
							</td>
						</tr>
						<tr>	
							<td>Type:</td>
							<td class="inputValue">
								<c:if test="${ not empty defectTracker.defectTrackerType.id }">
									<script>
										var initialTrackerTypeId = '<c:out value="${ defectTracker.defectTrackerType.id }"/>';
									</script>
								</c:if>
								<form:select style="margin:5px;" id="defectTrackerTypeSelect" path="defectTrackerType.id">
									<form:options items="${ defectTrackerTypeList }" itemValue="id" itemLabel="name" />
								</form:select>
							</td>
							<td style="padding-left: 5px">
								<form:errors path="defectTrackerType.id" cssClass="errors" />
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<div class="modal-footer">
				<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
				<button type="submit" class="btn btn-primary">Create Defect Tracker</button>
			</div>
		</form:form>
	</div>
</body>