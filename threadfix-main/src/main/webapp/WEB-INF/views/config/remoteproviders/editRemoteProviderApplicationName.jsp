<script type="text/ng-template" id="editRemoteProviderApplicationName.html">

    <div class="modal-header">
        <h4 id="myModalLabel">
            Edit Name for {{ object.nativeName || object.nativeId }}
        </h4>
    </div>

    <div ng-form="form" class="modal-body">
        <table style="border-spacing:10" class="modal-form-table">
            <tbody>
                <tr>
                    <td style="width: 100px">Custom Name</td>
                    <td>
                        <input type="text"
                               id="customName"
                               name="customName"
                               ng-model="object.customName"
                               placeholder="{{ object.nativeName || object.nativeId }}"
                               ng-maxlength="100"
                               focus-on="true"
                                />
                    </td>
                    <td>
                        <span class="errors" ng-show="form.customName.$dirty && form.customName.$error.maxlength">Maximum length is 100 characters.</span>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>