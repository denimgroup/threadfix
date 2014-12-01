<script type="text/ng-template" id="editRemoteProviderApplicationName.html">

    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Name for {{ object.nativeId }}
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <table style="border-spacing:10" class="modal-form-table">
            <tbody>
                <tr>
                    <td>Custom Name</td>
                    <td>
                        <input type="text" id="customName" ng-model="object.customName" placeholder="{{object.nativeId}}"/>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>