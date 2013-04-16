<%@ include file="/common/taglibs.jsp"%>

<body id="table">

	<spring:url value="/reports/ajax" var="emptyUrl"></spring:url>	

	<div>
		<c:if test="${ csvEnabled }">
			<a id="submitTeamModal" class="btn btn-primary"
					onclick="javascript:submitAjaxReport('<c:out value="${ emptyUrl }"/>', '#reportForm', '#formDiv', '#successDiv', ${ reportId }, 2);return false;">
				Export CSV
			</a>
		</c:if>
										
		<a id="submitTeamModal" class="btn btn-primary"
				onclick="javascript:submitAjaxReport('<c:out value="${ emptyUrl }"/>', '#reportForm', '#formDiv', '#successDiv', ${ reportId }, 3);return false;">
			Export PDF
		</a>
	</div>
	${jasperReport}
	
	<script>window.onload=function(){$('p').each(function(index) { $(this).css('line-height','1.5');});};</script>
</body>
