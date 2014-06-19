
<tab id="unmappedFindingTab" ng-controller="ScanUnmappedFindingTableController" heading="{{ heading }}" ng-show="numFindings && numFindings > 0">

    <h4 style="padding-top:8px">Findings Without Vulnerabilities</h4>

    <div class="alert">
        <strong>Warning!</strong>
        There are two steps to create vulnerabilities for these scan results.
        First, click Create Mapping for each type until each row has a value in the CWE column.
        Then re-upload your scan.
    </div>

    <%@ include file="../../scans/unmappedTable.jsp" %>
</tab>