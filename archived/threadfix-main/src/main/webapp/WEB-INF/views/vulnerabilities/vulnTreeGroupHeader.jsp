<div class="accordion-header" style="height:40px;padding: 8px 1px 4px 10px;" ng-show="element.totalVulns > 10 || treeApplication || treeTeam">
    <ul style="width:190px; float:left" class="nav nav-pills" ng-show="showPagination(element, 10)">
        <li id="show10{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
        <li id="show25{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
    </ul>
    <ul style="width:190px; float:left" class="nav nav-pills" ng-show="showPagination(element, 25)">
        <li id="show10{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
        <li id="show25{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
        <li id="show50{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
    </ul>
    <ul style="width:190px; float:left" class="nav nav-pills" ng-show="showPagination(element, 50)">
        <li id="show10{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
        <li id="show25{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
        <li id="show50{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
        <li id="show100{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 100 }"><a ng-click="updateElementTable(element, 100, 1)">100</a></li>
    </ul>
    <span style="margin:2px;float:left;" ng-form="form" class="pagination" ng-show="element.totalVulns > element.numberToShow">
        <!-- We may want to think about writing this out the long way for QA -->
        <pagination id="pagination{{ category.name }}{{ element.genericVulnerability.displayId }}"
                    class="no-margin"
                    total-items="element.totalVulns / element.numberToShow * 10"
                    max-size="5"
                    ng-model="element.page"
                    page="element.page"
                    direction-links="false"
                    boundary-links="true"
                    ng-click="updateElementTable(element, element.numberToShow, element.page)"></pagination>
    </span>
    <span ng-show="treeApplication || treeTeam" class="vuln-tree-checkbox">
        Check All
        <input id="checkCategory{{ category.name }}{{ element.genericVulnerability.displayId }}" type="checkbox" ng-model="element.checked" ng-change="applyElementChecked(element)" style="margin-top: -3px"/>
    </span>
</div>