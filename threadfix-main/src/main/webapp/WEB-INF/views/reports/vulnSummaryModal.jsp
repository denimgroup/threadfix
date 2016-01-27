<script type="text/ng-template" id="vulnSummaryModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Vulnerabilities Summary</h4>
        <div ng-show="headers" class="modal-body">
            <table >
                <tbody>
                <tr ng-repeat="header in headers">
                    <td id="header{{ $index }}" style="text-align:left;" ng-style="{color: headerColor}"> <b>{{ header }} </b></td>
                </tr>
                </tbody>
            </table>
        </div>
    </div>

    <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

    <div ng-hide="loading" class="modal-body">
        <table class="table table-striped">
            <thead>
            <tr>
                <th class="short first">CWE ID</th>
                <th class="long">CWE Name</th>
                <th class="short">Severity</th>
                <th class="short last">Quantity</th>
            </tr>
            </thead>
            <tbody id="vulnTableBody">
            <tr ng-repeat="category in categories">
                <td id="cweId{{ category.cweId }}">{{ category.cweId }}</td>
                <td id="cweName{{ category.cweId }}" style="word-wrap: break-word;">{{ category.secondaryPivotName }}</td>
                <td id="severity{{ category.cweId }}" generic-severity="{{ category.severityStr }}" class="break-word-header"></td>
                <td id="quantity{{ category.cweId }}" >{{ category.numResults }}</td>
            </tr>
            <tr ng-hide="categories || loading">
                <td colspan="4" style="text-align:center;">No Data Found.</td>
            </tr>

            </tbody>
        </table>
    </div>
    <div class="modal-footer">
        <span id="errorSpan" class="errors" style="float:left">{{ error }}</span>
        <button class="btn" data-dismiss="modal" aria-hidden="true" ng-click="cancel()" id="closeVulnerabilitiesSummary">Close</button>
        <security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
            <button id="submit"
                    class="btn btn-primary"
                    ng-hide="loading"
                    ng-click="goToDetail()">Details</button>
        </security:authorize>
    </div>
</script>