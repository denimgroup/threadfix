
<tab id="unmappedFindingTab" ng-controller="ScanUnmappedFindingTableController" heading="{{ heading }}"
     ng-click="setTab('Unmapped Findings')" active="tab.unmappedFindings" ng-show="numFindings && numFindings > 0">

    <h4 style="padding-top:8px">Findings Without Vulnerabilities</h4>

    <%@ include file="../../scans/unmappedTable.jsp" %>
</tab>