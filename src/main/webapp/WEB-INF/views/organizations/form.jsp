<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ organization.new }">New </c:if>Organization</title>
</head>

<body id="apps">
	<h2><c:if test="${ organization.new }">New </c:if>Organization</h2>
	
<spring:url value="" var="emptyUrl"></spring:url>	
<form:form modelAttribute="organization" method="post" autocomplete="off" action="${ fn:escapeXml( emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Name:</td>
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
<c:when test="${ organization.new }">
	<input id="submitButton" type="submit" value="Add Organization" />
	<spring:url value="/organizations" var="orgUrl" />
</c:when>
<c:otherwise>
	<input id="updateButton"type="submit" value="Update Organization" />
	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ organization.id }" />
	</spring:url>
</c:otherwise>
</c:choose>
	<span style="padding-left: 10px"><a href="${ fn:escapeXml(orgUrl) }">Cancel</a></span>
</form:form>
</body>