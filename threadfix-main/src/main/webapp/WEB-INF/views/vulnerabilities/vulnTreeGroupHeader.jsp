<div class="accordion-header" style="height:40px;padding: 8px 1px 4px 10px;" ng-show="element.totalVulns > 10 || treeApplication">
    <span ng-if="element.totalVulns > 10">
        <ul style="width:190px; float:left" class="nav nav-pills">
            <li ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
            <li ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
            <li ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
            <li ng-class="{ active: element.numberToShow === 100 }"><a ng-click="updateElementTable(element, 100, 1)">100</a></li>
        </ul>
    </span>
    <span ng-if="element.totalVulns < 11">
        <ul style="width:190px; float:left" class="nav nav-pills">
            <li ng-class="{ active: element.numberToShow === 10 }"> <a ng-disabled="true">10</a></li>
            <li ng-class="{ active: element.numberToShow === 25 }"> <a ng-disabled="true">25</a></li>
            <li ng-class="{ active: element.numberToShow === 50 }"> <a ng-disabled="true">50</a></li>
            <li ng-class="{ active: element.numberToShow === 100 }"><a ng-disabled="true">100</a></li>
        </ul>
    </span>
    <span style="margin:2px;float:left;" ng-form="form" class="pagination" ng-show="element.totalVulns > element.numberToShow">
        <pagination class="no-margin"
                    total-items="element.totalVulns / element.numberToShow * 10"
                    max-size="5"
                    ng-model="element.page"
                    page="element.page"
                    direction-links="false"
                    boundary-links="true"
                    ng-click="updateElementTable(element, element.numberToShow, element.page)"></pagination>
    </span>
    <span ng-show="treeApplication" class="vuln-tree-checkbox">
        <input type="checkbox" ng-model="element.checked" ng-change="applyElementChecked(element)"/>
    </span>
</div>