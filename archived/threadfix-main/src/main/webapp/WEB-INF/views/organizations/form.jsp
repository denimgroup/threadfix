<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ organization['new'] }">New </c:if>Team</title>
</head>

<body id="apps">
	<h2><c:if test="${ organization['new'] }">New </c:if>Team</h2>
	
<spring:url value="" var="emptyUrl"></spring:url>	
<form:form modelAttribute="organization" method="post" autocomplete="off" action="${ fn:escapeXml( emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Name:</td>
				<td class="inputValue">
					<form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
				</td>
				<td style="padding-left:5px">
					<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	<br/>
<c:choose>
<c:when test="${ organization['new'] }">
	<input id="submitButton" type="submit" value="Add Team" />
	<spring:url value="/teams" var="orgUrl" />
	<span style="padding-left: 10px"><a href="${ fn:escapeXml(orgUrl) }">Home</a></span>
</c:when>
<c:otherwise>
	<input id="updateButton"type="submit" value="Update Team" />
	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ organization.id }" />
	</spring:url>
	<span ng-non-bindable style="padding-left: 10px"><a href="${ fn:escapeXml(orgUrl) }">Back to Team <c:out value="${ organization.name }"/></a></span>
</c:otherwise>
</c:choose>
	
</form:form>
</body>