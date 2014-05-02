<%@ include file="/common/taglibs.jsp"%>

<body id="table">

    <span id="appDropDown">
        <c:if test="${ csvEnabled }">
            <a id="csvLink" class="btn btn-primary"
               target="_blank"
               ng-href="{{ base }}/ajax/export/{{ application.id }}/{{ team.id }}/{{ reportId }}/2{{ csrfToken }}">
                Export CSV
            </a>
        </c:if>

        <c:if test="${ pdfEnabled }">
            <a id="pdfLink" class="btn btn-primary"
               target="_blank"
               ng-href="{{ base }}/ajax/export/{{ application.id }}/{{ team.id }}/{{ reportId }}/3{{ csrfToken }}">
                Export PDF
            </a>
        </c:if>
    </span>

    <div id="reportDiv" style="overflow: auto">
        <c:if test="${ showEmptyBox && empty jasperReport }">
            <%@include file="/WEB-INF/views/reports/emptyReport.jspf" %>
        </c:if>
        ${jasperReport}
    </div>

    <script>window.onload=function(){$('p').each(function(index) { $(this).css('line-height','1.5');});};</script>
</body>