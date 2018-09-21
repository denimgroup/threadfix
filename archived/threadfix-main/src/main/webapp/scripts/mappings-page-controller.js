var myAppModule = angular.module('threadfix');

myAppModule.controller('MappingsPageController', function ($scope) {

    //this is needed because the unmapped findings table needs a parent with this property.
    $scope.currentUrl = "/mappings/index";

});