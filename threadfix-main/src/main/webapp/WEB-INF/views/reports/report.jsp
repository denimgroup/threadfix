<%@ include file="/common/taglibs.jsp"%>

<body id="table">
	
	<div id="reportDiv" 
			data-report-id="<c:out value="${ reportId }"/>"
			data-show-csv-export="<c:if test="${ csvEnabled }">1</c:if>" 
			data-show-pdf-export="<c:if test="${ pdfEnabled }">1</c:if>">
			
		<c:if test="${ showEmptyBox && empty jasperReport }">
			<%@include file="/WEB-INF/views/reports/emptyReport.jspf" %>
		</c:if>
		${jasperReport}
	</div>
	
	<script>window.onload=function(){$('p').each(function(index) { $(this).css('line-height','1.5');});};</script>
</body>
