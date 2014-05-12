<div ng-show="vulnTree" class="vuln-tree">

    <div ng-repeat="element in vulnTree">
        <span ng-hide="element.expanded" ng-click="toggleOn" class="icon icon-plus-sign"></span>
        <span ng-show="element.expanded" ng-click="element.expanded = false" class="icon icon-minus-sign"></span>
        <span class="badge" ng-class="{
                            'badge-important': element.intValue === 5,
                            'badge-warning': element.intValue === 4,
                            'badge-success': element.intValue === 3,
                            'badge-info': element.intValue === 2 || element.intValue === 1
                            }">
            {{ element.numResults }}
        </span>
        {{ element.genericVulnerability.name | shortCweNames }}
    </div>

</div>