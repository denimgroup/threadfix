var myAppModule = angular.module('threadfix')

myAppModule.controller('HeaderController', function ($scope, $window, $rootScope) {

    $scope.goTo = function(url) {
        $window.location.href = $rootScope.urlRoot + url + $rootScope.csrfToken;
    }

});