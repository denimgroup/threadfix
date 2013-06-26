<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty errorMessage }">
	<div class="alert alert-error">
		<button class="close" data-dismiss="alert" type="button">×</button>
		<c:out value="${ errorMessage }"/>
	</div>
</c:if>