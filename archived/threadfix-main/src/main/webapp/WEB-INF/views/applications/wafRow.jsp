<%@ include file="/common/taglibs.jsp"%>

<td style="padding:5px;">WAF</td>
<c:choose>
	<c:when test="${ empty application.waf }">
	<td style="padding:5px;" class="inputValue">
		<div id="appWafDiv">
			<a id="addWafButton" role="button" class="btn">Add</a>
		</div>
	</td>
	</c:when>
	<c:otherwise>
		<td style="padding:5px;" class="inputValue">
			<spring:url value="/wafs/{wafId}" var="wafUrl">
				<spring:param name="wafId" value="${ application.waf.id }"/>
			</spring:url>
			<a id="wafText"
					<c:if test="${ addedWaf }">
						data-added-waf="true"
					</c:if>
					href="${ fn:escapeXml(wafUrl) }">
				<span ng-non-bindable><c:out value="${ application.waf.name }"/></span>
			</a>
			<em ng-non-bindable>(<c:out value="${ application.waf.wafType.name }"/>)</em>
		</td>
		<td style="padding:5px;">
			<a id="editWafButton" href="#addWaf" role="button" class="btn" data-toggle="modal">Edit</a>
		</td>
	</c:otherwise>
</c:choose>
