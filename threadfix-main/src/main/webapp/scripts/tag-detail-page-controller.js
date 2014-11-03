var myAppModule = angular.module('threadfix')

myAppModule.controller('TagDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder) {

    $scope.tagId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.currentUrl = "/configuration/tags/" + $scope.tagId;
    $scope.$on('rootScopeInitialized', function() {
        $scope.loading = true;
        $http.get(tfEncoder.encode($scope.currentUrl + '/objects')).
            success(function(data, status, headers, config) {
                $scope.loading = false;
                if (data.success) {
                    $scope.appList = data.object.appList;
                    $scope.commentList = data.object.commentList;
                    getVulnList();
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.loading = false;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    var getVulnList = function(){
        var vulnMap = {};
        $scope.commentList.forEach(function(comment) {
            if (comment.commentInfo.vulnerabilityId) {
                if (!vulnMap[comment.commentInfo.vulnerabilityId]) {
                    vulnMap[comment.commentInfo.vulnerabilityId] = {
                        vulnId : comment.commentInfo.vulnerabilityId,
                        vulnName: comment.commentInfo.vulnerabilityName,
                        appId : comment.commentInfo.applicationId,
                        appName : comment.commentInfo.applicationName,
                        teamId : comment.commentInfo.teamId,
                        teamName : comment.commentInfo.teamName,
                        comments : [{
                            commentId: comment.commentInfo.commentId,
                            comment: comment.commentInfo.comment,
                            tags: comment.commentInfo.tags,
                            username: comment.commentInfo.username,
                            time: comment.commentInfo.time
                        }]
                    }
                } else {
                    vulnMap[comment.commentInfo.vulnerabilityId].comments.push({
                        commentId: comment.commentInfo.commentId,
                        comment: comment.commentInfo.comment,
                        tags: comment.commentInfo.tags,
                        username: comment.commentInfo.username,
                        time: comment.commentInfo.time
                    })
                }
            }
        })

        $scope.vulnList = [];
        var keys = Object.keys(vulnMap);
        keys.forEach(function(key){
            $scope.vulnList.push(vulnMap[key]);
        })

        $scope.vulnList.sort(function(vuln1, vuln2){
            return vuln1.comments.length - vuln2.comments.length;
        })
    }

    $scope.goToApp = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    }

    $scope.goToTeam = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id);
    }

    $scope.goToAppFromVuln = function(vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.teamId + "/applications/" + vuln.appId);
    }

    $scope.goToTeamFromVuln = function(vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.teamId);
    }

    $scope.goToTag = function(tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id +"/view");
    }

    $scope.goToVuln = function(vuln) {
        $window.location.href = tfEncoder.encode("/organizations/" + vuln.teamId + "/applications/" + vuln.appId + "/vulnerabilities/" + vuln.vulnId);
    };

    $scope.expand = function() {
        $scope.vulnList.forEach(function(vuln) {
            vuln.expanded = true;
        });
    };

    $scope.contract = function() {
        $scope.vulnList.forEach(function(vuln) {
            vuln.expanded = false;
        });
    };

    $scope.toggle = function(vuln) {
        if (typeof vuln.expanded === "undefined") {
            vuln.expanded = false;
        }
        vuln.expanded = !vuln.expanded;
    };

});
