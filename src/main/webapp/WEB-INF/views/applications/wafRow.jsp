<%@ include file="/common/taglibs.jsp"%>

<td>WAF</td>
<c:choose>
	<c:when test="${ empty application.waf }">
	<td class="inputValue">
		<div id="appWafDiv">
			<a href="#addWaf" role="button" class="btn" data-toggle="modal">Add WAF</a>
		</div>
	</td>
	</c:when>
	<c:otherwise>
	<td class="inputValue">
		<spring:url value="/wafs/{wafId}" var="wafUrl">
			<spring:param name="wafId" value="${ application.waf.id }"/>
		</spring:url>
		<a id="wafText" href="${ fn:escapeXml(wafUrl) }"><c:out value="${ application.waf.name }"/></a>
		<em>(<c:out value="${ application.waf.wafType.name }"/>)</em>
	</td>
	<td>
		<a href="#addWaf" role="button" class="btn" data-toggle="modal">Edit WAF</a>
	</td>
	</c:otherwise>
</c:choose>
