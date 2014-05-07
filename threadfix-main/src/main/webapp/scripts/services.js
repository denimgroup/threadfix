var threadfixModule = angular.module('threadfix')

threadfixModule.factory('tfEncoder', function($rootScope, $location) {

    var tfEncoder = {};

    tfEncoder.encode = function(path) {
        return $rootScope.urlRoot + path + $rootScope.csrfToken;
    }

    tfEncoder.encodeRelative = function(path) {
        return $location.path() + path + $rootScope.csrfToken;
    }

    tfEncoder.urlRoot = $rootScope.urlRoot;

    return tfEncoder;
});

threadfixModule.factory('threadfixAPIService', function($location, $http, tfEncoder, $rootScope) {

    var threadfixAPIService = {};

    threadfixAPIService.getTeams = function() {
        return $http({
            method: 'GET',
            url: tfEncoder.encode('/organizations/jsonList')
        });
    };

    threadfixAPIService.loadAppTableReport = function(id) {
        var url = '/organizations/' + id + '/getReport';

        return $http({
            method: 'GET',
            url: tfEncoder.encode(url)
        });
    };

    threadfixAPIService.loadReport = function(url, query) {
        return $http({
            method: 'GET',
            url: tfEncoder.encode(url) + query
        });
    };

    threadfixAPIService.loadVulns = function() {
        return $http({
            method: 'GET',
            url: $location.path() + "/vulns" + $rootScope.csrfToken
        });
    }

    return threadfixAPIService;
});

threadfixModule.factory('threadFixModalService', function($http) {

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

    threadFixModalService.deleteElement = function(elementList, element) {
        var index = elementList.indexOf(element);

        if (index > -1) {
            elementList.splice(index, 1);
        }

        if (elementList.length === 0) {
            elementList = undefined;
        }
    };

    threadFixModalService.addElement = function(elementList, element) {
        if (!elementList) {
            elementList = [];
        }
        elementList.push(element);
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