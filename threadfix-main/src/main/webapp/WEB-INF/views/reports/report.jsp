<%@ include file="/common/taglibs.jsp"%>

<body id="table">

    <div id="reportDiv" ng-init="csvEnabled = '<c:if test="${ csvEnabled }">1</c:if>'; pdfEnabled = '<c:if test="${ csvEnabled }">1</c:if>'">

        <c:if test="${ showEmptyBox && empty jasperReport }">
            <%@include file="/WEB-INF/views/reports/emptyReport.jspf" %>
        </c:if>
        ${jasperReport}
    </div>

    <script>window.onload=function(){$('p').each(function(index) { $(this).css('line-height','1.5');});};</script>
</body>