<div class="modal-header">
    <h4>{{ config.heading }}</h4>
</div>
<div class="modal-body" ng-form="form">
    <table>
        <%@ include file="/WEB-INF/views/applications/forms/addScheduledJobFields.jsp" %>
    </table>
</div>
<%@ include file="/WEB-INF/views/modal/footer.jspf" %>