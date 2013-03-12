<%@ include file="/common/taglibs.jsp"%>

<body id="table">
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
</body>