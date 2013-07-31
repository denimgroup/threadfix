<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty application.scans }"> 

<spring:url value="{appId}/falsepositives/mark" var="markFPUrl">
   	<spring:param name="appId" value="${ application.id }" />
</spring:url>
<form:form modelAttribute="falsePositiveModel" method="post" action="${ fn:escapeXml(markFPUrl) }">

<spring:url value="{appId}/table" var="tableUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/table/close" var="closeUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<spring:url value="{appId}/falsePositives/mark" var="fpUrl">
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>

<c:if test="${ canModifyVulnerabilities || canSubmitDefects }">
   	<div id="btnDiv1" class="btn-group">
		<button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li class="submitDefectActionLink"
				<c:if test="${ empty application.defectTracker }">
					style="display:none"
				</c:if>
			>
				<a id="submitDefectButton" href="#submitDefectModal" data-toggle="modal">
					Submit Defect
				</a>
			</li>
			<li class="missingDefectTrackerMessage" id = "missingDefectTrackerMessage"
				<c:if test="${ not empty application.defectTracker }">
					style="display:none"
				</c:if>
				<c:if test="${ empty application.defectTracker && !canManageApplications }">
					data-has-no-manage-app-permisson="true"
				</c:if>
			>
				<a class="missingDefectTrackerMessage" href="#">
					Submit Defect
				</a>
			</li>
			
			<li class="submitDefectActionLink"
				<c:if test="${ empty application.defectTracker }">
					style="display:none"
				</c:if>
			>
				<a class="submitDefectActionLink" id="mergeDefectButton" href="#mergeDefectModal" data-toggle="modal">
					Merge Defect
				</a>
			</li>
			<li class="missingDefectTrackerMessage"
				<c:if test="${ not empty application.defectTracker }">
					style="display:none"
				</c:if>
				<c:if test="${ empty application.defectTracker && !canManageApplications }">
					data-has-no-manage-app-permisson="true"
				</c:if>
			>
				<a class="missingDefectTrackerMessage" href="#" >
					Merge Defect
				</a>
			</li>
						
			<c:if test="${ canModifyVulnerabilities}"><li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li></c:if>
			<c:if test="${ canModifyVulnerabilities}"><li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li></c:if>
		</ul>
	</div>
</c:if>

<span style="float:right">
	<a class="btn" id="expandAllVulns">Expand All</a>
	<a class="btn" id="collapseAllVulns">Collapse All</a>
</span>

<%@ include file="/WEB-INF/views/applications/tabs/filter.jspf" %>

<%@ include file="/WEB-INF/views/applications/tabs/defaultTableDiv.jspf" %>

<c:if test="${ canModifyVulnerabilities || canSubmitDefects }">
   	<div id="btnDiv2" class="btn-group">
		<button id="actionButton2" class="btn dropdown-toggle" data-toggle="dropdown" type="button">Action <span class="caret"></span></button>
		<ul class="dropdown-menu">
			<li class="submitDefectActionLink"
				<c:if test="${ empty application.defectTracker }">
					style="display:none"
				</c:if>
			>
				<a class="submitDefectActionLink" id="submitDefectButton" href="#submitDefectModal" data-toggle="modal">
					Submit Defect
				</a>
			</li>
			<li class="missingDefectTrackerMessage"
				<c:if test="${ not empty application.defectTracker }">
					style="display:none"
				</c:if>
				<c:if test="${ empty application.defectTracker && !canManageApplications }">
					data-has-no-manage-app-permisson="true"
				</c:if>
			>
				<a class="missingDefectTrackerMessage" href="#" >
					Submit Defect
				</a>
			</li>		

			<li class="submitDefectActionLink"
				<c:if test="${ empty application.defectTracker }">
					style="display:none"
				</c:if>
			>
				<a class="submitDefectActionLink" id="mergeDefectButton" href="#mergeDefectModal" data-toggle="modal">
					Merge Defect
				</a>
			</li>
			<li class="missingDefectTrackerMessage"
				<c:if test="${ not empty application.defectTracker }">
					style="display:none"
				</c:if>
				<c:if test="${ empty application.defectTracker && !canManageApplications }">
					data-has-no-manage-app-permisson="true"
				</c:if>
			>
				<a class="missingDefectTrackerMessage" href="#" >
					Merge Defect
				</a>
			</li>

			<c:if test="${ canModifyVulnerabilities}"><li><a id="markClosedButton" onclick="javascript:submitVulnTableOperation('${ closeUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark Closed</a></li></c:if>
			<c:if test="${ canModifyVulnerabilities}"><li><a id="markFalsePositiveButton" onclick="javascript:submitVulnTableOperation('${ fpUrl }', '#errorDiv', '#teamTable');return false;" href="#">Mark False Positive</a></li></c:if>
		</ul>
	</div>
</c:if>

</form:form>

</c:if>
