<script type="text/ng-template" id="editDescriptionFindingForm.html">

    <div class="modal-header">
        <h4>Edit Description Finding {{object.id}}</h4>
    </div>
    <div ng-form="form" class="modal-body" >
        <table class="modal-form-table">
            <tbody>
            <tr>
                <td style="padding:5px;">Description</td>
                <td class="inputValue">
                    <textarea style="width:350px;" id="descriptionInput" name="longDescription" ng-model="object.longDescription" rows="5" cols="50"></textarea>
                </td>
                <td>
                    <span class="errors" ng-show="object.longDescription_error">{{ object.longDescription_error }}</span>
                </td>
            </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>