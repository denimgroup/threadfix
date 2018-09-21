<script type="text/ng-template" id="vulnTaggingForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Batch Tagging Vulnerabilities</h4>
    </div>
    <div ng-form="form" class="modal-body input-group">
        <table class="modal-form-table">
            <tr class="left-align">
                <td>Tag</td>
                <td class="left-align">
                    <multi-select
                            id-prefix="tags"
                            id="tagSelect"
                            input-model="config.tags"
                            output-model="object.tags"
                            button-label="name"
                            item-label="name"
                            tick-property="selected"
                            >
                    </multi-select>
                </td>
            </tr>
        </table>
        <div style="height:200px"></div>
    </div>

    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>