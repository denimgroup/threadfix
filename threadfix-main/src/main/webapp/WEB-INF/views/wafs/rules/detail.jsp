<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>WAF Rule Statistics</title>
</head>

<body>
	<spring:url value="/wafs/{wafId}" var="wafUrl">
		<spring:param name="wafId" value="${ wafRule.waf.id }"/>
	</spring:url>
	<a href="${ fn:escapeXml(wafUrl) }">Back to WAF ${ wafRule.waf.name} </a>
	
	<h3>WAF Rule ${ wafRule.nativeId } Statistics:</h3>
	
	This rule has been fired ${ fn:length(wafRule.securityEvents) } times:
	<br/><br/>
		
	<c:forEach var="event" items="${ wafRule.securityEvents }">
		<spring:url value="{wafRuleId}/events/{eventId}" var="eventUrl">
			<spring:param name="wafRuleId" value="${ wafRule.id }"/>
			<spring:param name="eventId" value="${ event.id }"/>
		</spring:url>
		<a href="${ fn:escapeXml(eventUrl) }" ng-non-bindable>
		<fmt:formatDate value="${event.importTime.time}" type="both" dateStyle="short" timeStyle="medium" /> -- <c:out value="${ event.attackType }"/>
		</a>
		<br/>
	</c:forEach>
</body>