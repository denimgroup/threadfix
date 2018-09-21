<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Select a Survey</title>
</head>

<body id="apps">
	<h2>Select a Survey</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="surveyResult" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td>Team:</td>
				<td class="inputValue" ng-non-bindable>
					<c:out value="${ surveyResult.organization.name }" />
				</td>
			</tr>
			<tr>
				<td>Survey:</td>
				<td class="inputValue">
					<form:select path="survey.id">
						<form:options items="${ surveyList }" itemValue="id" itemLabel="name" />
					</form:select>
				</td>
			</tr>
		</table>
		<br />
		<table>
			<tr>
				<td>
					<input name="surveys/continue" value="Continue" type="image" src="<spring:url value="/images/continue_button.png" />" 
						onmouseover="javascript:this.src='<spring:url value="/images/continue_button_hover.png" />';" 
						onmouseout="javascript:this.src='<spring:url value="/images/continue_button.png" />';" />
				</td>
				<td style="padding-left:10px">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ surveyResult.organization.id }" />
					</spring:url>
					<a href="${ fn:escapeXml(orgUrl) }">Cancel</a>
				</td>
			</tr>
		</table>
	</form:form>
</body>