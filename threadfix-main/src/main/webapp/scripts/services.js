var threadfixModule = angular.module('threadfix')

threadfixModule.factory('threadfixAPIService', function($http) {

    var apiKey = "M4DpC1MLqK4YRG33DxHW4PaIM4FlvEowjlkbucERKg";

    var threadfixAPIService = {};

    threadfixAPIService.getTeams = function() {
        return $http({
            method: 'GET',
            url: '/rest/teams?apiKey=' + apiKey
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
                dataType : "text",
            });
        };

        return threadFixModalService;
    });