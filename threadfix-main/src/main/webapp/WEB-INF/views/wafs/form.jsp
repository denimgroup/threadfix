<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ waf['new'] }">New </c:if>WAF</title>
</head>

<body id="wafs">
	<h2><c:if test="${ waf['new'] }">New </c:if>WAF</h2>
	
<spring:url value="" var="emptyUrl"></spring:url>
<form:form modelAttribute="waf" method="post" action="${ fn:escapeXml(emptyUrl) }">
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Name:</td>
				<td class="inputValue">
					<form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="50"/>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Type:</td>
				<td class="inputValue">
					<form:select id="typeSelect" path="wafType.id">
						<form:options items="${ wafTypeList }" itemValue="id" itemLabel="name" />
					</form:select>
				</td>
				<td style="padding-left: 5px">
					<form:errors path="wafType.id" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	<br />
<c:choose>
<c:when test="${ waf['new'] }">
	<input id="addWafButton" type="submit" value="Add WAF" />
	<spring:url value="/wafs" var="wafUrl" />
</c:when>
<c:otherwise>
	<input id="updateWafButton" type="submit" value="Update WAF" />
	<spring:url value="/wafs/{wafId}" var="wafUrl">
		<spring:param name="wafId" value="${ waf.id }" />
	</spring:url>
</c:otherwise>
</c:choose>
	<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(wafUrl) }">Cancel</a></span>
</form:form>
</body>