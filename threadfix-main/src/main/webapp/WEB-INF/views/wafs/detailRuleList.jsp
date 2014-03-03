<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>
<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
		<c:if test="${ not empty waf.wafRules }">
		<h3>WAF Rule Statistics <a href="#statisticsDiv" data-toggle="collapse" >View Details</a></h3>
            <div id="statisticsDiv" class="container-fluid collapse">
				<c:forEach var="wafRule" items="${ waf.wafRules }">
				<spring:url value="/wafs/{wafId}/rule/{wafRuleId}" var="viewRuleUrl">
					<spring:param name="wafId" value="${ waf.id }"/>
					<spring:param name="wafRuleId" value="${ wafRule.id }"/>
				</spring:url>
				<a href="${ fn:escapeXml(viewRuleUrl) }"> <c:out value="${ wafRule.nativeId }"/> - fired <c:out value="${fn:length(wafRule.securityEvents)}" /> times</a>
				<br/>
			    </c:forEach>
            </div>
		</c:if>
		<c:if test="${ not empty rulesText }">
			<h3>WAF Rules:</h3>
            <spring:url value="/wafs/{wafId}/rules/download/app/{appId}" var="downloadRulesUrl">
                <spring:param name="wafId" value="${ waf.id }"/>
                <spring:param name="appId" value="${ selectedAppId }"/>
            </spring:url>
			<form id="form1" name="form1" method="post" action="${ fn:escapeXml(downloadRulesUrl) }">
				<input class="btn btn-primary" id="downloadWafRulesButton" type="submit" value="Download Waf Rules"/>
			</form><br/>
			<div id="wafrule">
				<pre><c:out value="${ rulesText }"/></pre>
			</div>
		</c:if>
