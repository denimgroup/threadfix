<script type="text/ng-template" id="userImportModal.html">
    <div class="modal-header">
        <h4 id="userImportModalLabel">Import Users</h4>
    </div>
    <div ng-form="form" class="modal-body">
        <table class="modal-form-table dataTable">
            <tr class="ng-scope">
                <td>Import Groups</td>
                <td><input id="importGroups" type="checkbox" name="importGroups" ng-model="object.importGroups"></td>
            </tr>
            <tr class="ng-scope">
                <td>Match Users to Groups</td>
                <td><input id="matchUser" type="checkbox" name="matchUsers" ng-model="object.matchUsers"></td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
