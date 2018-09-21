var myAppModule = angular.module('threadfix')

myAppModule.controller('InitController', function ($scope, $window, $rootScope, $log) {

    var setToken = function(oldValue, newValue) {
        $rootScope.csrfToken = $scope.csrfToken;

        if ($rootScope.urlRoot) {
            $rootScope.$broadcast('rootScopeInitialized');
        }

        $log.info('Token is ' + $scope.csrfToken);
    }

    var setRoot = function(oldValue, newValue) {
        $rootScope.urlRoot = $scope.urlRoot;

        if ($rootScope.csrfToken) {
            $rootScope.$broadcast('rootScopeInitialized');
        }

        $log.info('Root is ' + $scope.urlRoot);
    }

    $scope.$watch('csrfToken', setToken);
    $scope.$watch('urlRoot', setRoot);

});