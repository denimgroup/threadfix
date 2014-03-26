var myAppModule = angular.module('threadfix')

myAppModule.controller('HeaderController', function ($scope, $window, $rootScope, $log) {

    $scope.goTo = function(url) {
        $window.location.href = url + $scope.csrfToken;
    }

});