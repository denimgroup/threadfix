<script type="text/ng-template" id="graphConfig.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Graph Configuration</h4>
    </div>
    <div ng-form="form" class="modal-body" id="graphConfigModal">
        <table>
            <tr>
                <td>
                    <select size="15" style="float:left" class="span3" form="opts" ng-options="s.name for s in object" ng-model="selectedScanner">
                    </select>
                </td>
                <td>
                    <form action=""   style="text-align: left; margin-left: 60px; line-height: 30px; margin-top: -45px" class="span3" id="opts">

                        <input type="checkbox"  ng-model="selectedScanner.criticalVulns" onclick="selectedScanner.criticalVulns = true"> Critical<br/>
                        <input type="checkbox" ng-model="selectedScanner.highVulns" onclick="selectedScanner.highVulns = true"> High<br/>
                        <input type="checkbox" ng-model="selectedScanner.mediumVulns" onclick="selectedScanner.mediumVulns = true"> Medium<br/>
                        <input type="checkbox" ng-model="selectedScanner.lowVulns" onclick="selectedScanner.lowVulns = true"> Low<br/>
                        <input type="checkbox" ng-model="selectedScanner.infoVulns" onclick="selectedScanner.infoVulns = true"> Info<br/>
                        <input type="radio" value="Dynamic" name="type" checked onclick="document.getElementById('audit').style.visibility = 'hidden'"> Dynamic
                        <input type="radio" value="Static" name="type" onclick="document.getElementById('audit').style.visibility = 'visible'"> Static<br/>
                        <div id="audit" style="visibility: hidden">
                            <input type="checkbox" ng-model="selectedScanner.auditable" onclick="selectedScanner.auditable = true"> Audited
                        </div>
                    </form>
                </td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
