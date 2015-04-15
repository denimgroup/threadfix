var myAppModule = angular.module('threadfix');

myAppModule.controller('CheckLDAPController', function ($scope, $http, tfEncoder) {

    $scope.shouldDisable = function() {
        var returnValue = true;

        if ($scope.object) {
            returnValue = !($scope.object.activeDirectoryBase &&
                $scope.object.activeDirectoryUsername &&
                $scope.object.activeDirectoryCredentials &&
                $scope.object.activeDirectoryURL);
        }

        return returnValue;
    };

    $scope.$on('rootScopeInitialized', function() {
        var url = tfEncoder.encode('/configuration/settings/getLDAPSettings');
        $http.get(url).
            success(function(data) {

                if (data.success) {
                    $scope.object = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve LDAP settings. HTTP status was " + status;
            });
    });

  $scope.ok = function (valid) {
    var url = tfEncoder.encode('/configuration/settings/checkLDAP');

    if (valid) {
      $scope.loading = true;

      $http.post(url, $scope.object).
          success(function(data) {
            $scope.loading = false;

            if (data.success) {
              $scope.LDAPSuccessMessage = data.object;
            } else {
              $scope.error = "Failure: " + data.message;
            }
          }).
          error(function(data, status) {
            $scope.loading = false;
            $scope.error = "Failure. HTTP status was " + status;
          });
    }
  };

});