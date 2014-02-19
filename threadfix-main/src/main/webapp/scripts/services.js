var threadfixModule = angular.module('threadfix')

threadfixModule.factory('threadfixAPIService', function($http) {

    var threadfixAPIService = {};

    threadfixAPIService.getTeams = function(csrfToken) {
        return $http({
            method: 'GET',
            url: '/organizations/jsonList' + csrfToken
        });
    };

    threadfixAPIService.loadReport = function(team) {
        return $http({
            method: 'GET',
            url: team.graphUrl
        });
    };

    return threadfixAPIService;
});

threadfixModule.factory('threadFixModalService', function($http) {

        var apiKey = "M4DpC1MLqK4YRG33DxHW4PaIM4FlvEowjlkbucERKg";

        var threadFixModalService = {};

        threadFixModalService.post = function(url, data) {
            return $http({
                method: 'POST',
                url: url,
                data : data,
                contentType : "application/x-www-form-urlencoded",
                dataType : "text"
            });
        };

        return threadFixModalService;
    });

threadfixModule.factory('focus', function ($rootScope, $timeout) {
    return function(name) {
        $timeout(function (){
            $rootScope.$broadcast('focusOn', name);
        });
    }
});