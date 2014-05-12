<div ng-show="vulnTree" class="vuln-tree">
    <h3>Results</h3>

    <div ng-hide="vulnTree && vulnTree.length > 0">
        No results found.
    </div>

    <div ng-repeat="category in vulnTree" ng-show="category.total > 0">
        <span ng-hide="category.expanded" ng-click="category.expanded = true" class="icon icon-plus-sign"></span>
        <span ng-show="category.expanded" ng-click="category.expanded = false" class="icon icon-minus-sign"></span>
        {{ category.name }}
        <span class="badge" ng-class="{
                                'badge-important': category.intValue === 5,
                                'badge-warning': category.intValue === 4,
                                'badge-success': category.intValue === 3,
                                'badge-info': category.intValue === 2 || element.intValue === 1
                                }">
            {{ category.total }}
        </span>
        <div ng-repeat="element in category.entries" ng-show="category.expanded">

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

</div>