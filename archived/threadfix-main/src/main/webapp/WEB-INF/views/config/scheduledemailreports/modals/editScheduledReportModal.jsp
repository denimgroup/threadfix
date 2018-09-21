<script type="text/ng-template" id="editScheduledReportModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Edit Scheduled Email Report
            <span class="delete-span">
                <a id="deleteButton"
                        ng-click="showDeleteDialog('Scheduled Email Report')"
                        class="btn btn-danger header-button"
                        type="submit">Delete</a>
            </span>
        </h4>
    </div>
    <%@ include file="/WEB-INF/views/config/scheduledemailreports/modals/scheduledReportModalBody.jsp" %>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
