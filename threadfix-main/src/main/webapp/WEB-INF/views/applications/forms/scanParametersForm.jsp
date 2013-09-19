<%@ include file="/common/taglibs.jsp"%>

<spring:url value="/organizations/{orgId}/applications/{appId}/setParameters" var="setParametersUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="scanParametersForm" 
		style="margin-bottom:0px" 
		modelAttribute="scanParametersBean" 
		method="post" 
		autocomplete="off" 
		action="${ fn:escapeXml(setParametersUrl) }" 
		enctype="multipart/form-data">
	<div class="modal-body">
		<c:if test="${ not empty message }">
			<div class="alert alert-error">
				<button class="close" data-dismiss="alert" type="button">×</button>
				<c:out value="${ message }"/>
			</div>
		</c:if>
		
		<table>
			<tr>
				<td class="right-align" style="padding:5px;">Application Type</td>
				<td class="left-align"  style="padding:5px;">
					<form:select path="applicationType" 
						items="${ applicationTypes }"
						itemLabel="displayName"/>
				</td>
			</tr>
			<tr>
				<td class="right-align" style="padding:5px;">Source Code Access Level</td>
				<td class="left-align"  style="padding:5px;">
					<form:select path="sourceCodeAccessLevel" 
						items="${ sourceCodeAccessLevels }"
						itemLabel="displayName"/>
				</td>
			</tr>
			<tr>
				<td class="right-align" style="padding:5px;">Type Matching Strategy</td>
				<td class="left-align"  style="padding:5px;">
					<form:select path="typeMatchingStrategy" 
						items="${ typeMatchingStrategies }"
						itemLabel="displayName"/>
				</td>
			</tr>
			<tr>
				<td class="right-align" style="padding:5px;">Source Code URL:</td>
				<td class="left-align"  style="padding:5px;">
					<form:input maxlength="250" path="sourceCodeUrl"/>
				</td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<button id="closeScanParametersModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="scanParametersSubmit" data-success-div="modal-footer" class="modalSubmit btn btn-primary">Submit</a>
	</div>
</form:form>
