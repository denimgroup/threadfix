<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not empty errorMessage }">
	<div class="alert alert-error">
		<c:if test="${ empty notCloseable }">
			<button class="close" data-dismiss="alert" type="button">×</button>
		</c:if>
		<c:out value="${ errorMessage }"/>
	</div>
</c:if>