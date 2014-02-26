<script type="text/ng-template" id="addWafModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Add WAF</h4>
    </div>
    <div id="addWafDivInForm" class="modal-body"
        <table>
            <tr>
                <td>WAF</td>
                <td class="inputValue">
                    <select style="margin:5px;" id="wafSelect" name="waf.id">
                        <option value="0" label="<none>" />
                        <option ng-repeat="waf in wafsList" value="{{ waf.id }}"> {{ waf.name }} </option>
                    <select>
                    <button class="btn" id="addWafButtonInModal" ng-click>Create New WAF</button>
                </td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>