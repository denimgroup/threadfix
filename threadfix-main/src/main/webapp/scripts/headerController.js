var myAppModule = angular.module('threadfix')

myAppModule.controller('HeaderController', function ($scope, $window) {

    $scope.goTo = function(url) {
        $window.location.href = url + $scope.csrfToken;
    }


});