<div class="accordion-header" style="height:40px;padding: 8px 1px 4px 10px;" ng-show="element.totalVulns > 10 || treeApplication">
    <ul style="width:190px; float:left" class="nav nav-pills">
        <span ng-if="element.totalVulns > 10 && element.totalVulns <= 25">
            <li id="show10{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
            <li id="show25{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
        </span>
        <span ng-if="element.totalVulns > 25 && element.totalVulns <= 50">
            <li id="show50{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
        </span>
        <span ng-if="element.totalVulns > 50 && element.totalVulns <= 100">
            <li id="show100{{ category.name }}{{ element.genericVulnerability.displayId }}" ng-class="{ active: element.numberToShow === 100 }"><a ng-click="updateElementTable(element, 100, 1)">100</a></li>
        </span>
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
    <span ng-show="treeApplication" class="vuln-tree-checkbox">
         <span ng-if="element.totalVulns < 10">
            Check All
         </span>
        <input id="checkCategory{{ category.name }}{{ element.genericVulnerability.displayId }}" type="checkbox" ng-model="element.checked" ng-change="applyElementChecked(element)" style="margin-top: -3px"/>
    </span>
</div>