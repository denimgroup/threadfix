<%@ include file="/common/taglibs.jsp"%>

<c:set var="successMessage" value="${ severitySuccessMessage }"/>
<div class="hide-after-submit">
	<%@ include file="/WEB-INF/views/successMessage.jspf"%>
</div>

<c:choose>
	<c:when test="${ type == 'Application' }">
		<spring:url value="/organizations/{orgId}/applications/{appId}/severityFilter/set" var="editFilterUrl">
			<spring:param name="orgId" value="${severityFilter.application.organization.id}"/>
			<spring:param name="appId" value="${severityFilter.application.id}"/>
		</spring:url>
	</c:when>
	<c:when test="${ type == 'Organization' }">
		<spring:url value="/organizations/{orgId}/severityFilter/set" var="editFilterUrl">
			<spring:param name="orgId" value="${severityFilter.organization.id}"/>
		</spring:url>
	</c:when>
	<c:otherwise>
		<spring:url value="/configuration/severityFilter/set" var="editFilterUrl">
		</spring:url>
	</c:otherwise>
</c:choose>

<form:form id="severityFilterForm" 
		style="margin-bottom:0px;" 
		modelAttribute="severityFilter" 
		method="post" 
		action="${ fn:escapeXml(editFilterUrl) }">
	<div class="modal-body">
	
	<table class="table noBorders">
		<tbody>
			<tr>
				<td style="width:130px">Enable Severity Filters</td>
				<td>
					<form:checkbox id="enabledBox" path="enabled"/>
				</td>
				<td><form:errors path="enabled" cssClass="errors" /></td>
			</tr>
		</tbody>
	</table>
	<table class="table noBorders">
		<thead>
			<tr>
				<th style="width:80px;">Severity</th>
				<th style="width:30px">Show</th>
				<th style="width:30px">Hide</th>
			</tr>
		</thead>
		<tbody>		
			<tr>
				<td>Critical</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showCritical" value="true"/>
				</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showCritical" value="false"/>
				</td>
				<td><form:errors path="showCritical" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>High</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showHigh" value="true"/>
				</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showHigh" value="false"/>
				</td>
				<td><form:errors path="showHigh" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Medium</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showMedium" value="true"/>
				</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showMedium" value="false"/>
				</td>
				<td><form:errors path="showMedium" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Low</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showLow" value="true"/>
				</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showLow" value="false"/>
				</td>
				<td><form:errors path="showLow" cssClass="errors" /></td>
			</tr>
			<tr>
				<td>Info</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showInfo" value="true"/>
				</td>
				<td class="centered">
					<form:radiobutton class="needsEnabled" path="showInfo" value="false"/>
				</td>
				<td><form:errors path="showInfo" cssClass="errors" /></td>
			</tr>
		</tbody>
	</table>
	</div>
	<a id="submitSeverityFilterForm" 
			class="modalSubmit btn btn-primary" 
			data-success-div="tabsDiv"
			data-form-div="severityFilterFormDiv"
			>
		Save Severity Filter Changes
	</a>
</form:form>
