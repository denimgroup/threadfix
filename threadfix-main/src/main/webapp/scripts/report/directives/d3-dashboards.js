var d3ThreadfixModule = angular.module('threadfix');

// Months Summary report
d3ThreadfixModule.directive('d3Vbars', ['$window', '$timeout', 'd3', 'd3Service', 'reportConstants', 'reportUtilities', 'threadFixModalService', 'vulnSearchParameterService',
    function($window, $timeout, d3, d3Service, reportConstants, reportUtilities, threadFixModalService, vulnSearchParameterService) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '='
            }
            ,
            link: function(scope, ele, attrs) {
                var margin = {top: 20, right: 20, bottom: 30, left: 60},
                    width = 422 - margin.left - margin.right,
                    height = 250 - margin.top - margin.bottom;

                var x = d3Service.getScaleOrdinalRangeBand(d3, [0, width], .1);

                var y = d3Service.getScaleLinearRange(d3, [height, 0]);

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);

                var xAxis = d3Service.getAxis(d3, x, "bottom");

                var yAxis = d3Service.getAxis(d3, y, "left");

                var svg = d3Service.getSvg(d3, ele[0], width + margin.left + margin.right, height + margin.top + margin.bottom)
                    .append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                var tip = d3Service.getTip(d3, 'd3-tip', [-10, 0], 'verticalBarTip')
                    .html(function(d) {
                        return "<strong>" + d.tip + ":</strong> <span style='color:red'>" + (d.y1 - d.y0) + "</span>";
                    });
                svg.call(tip);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    svg.selectAll('*').remove();

                    if (!data || data.length < 1) return;

                    barGraphData(d3, data, color, true, scope.label, reportConstants);

                    x.domain(data.map(function(d) { return d.title; }));
                    y.domain([0, d3.max(data, function(d) { return d.total; })]);

                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + height + ")")
                        .call(xAxis);

                    svg.append("g")
                        .attr("class", "y axis")
                        .call(yAxis);

                    var col = svg.selectAll(".title")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "g")
                        .attr("transform", function(d) { return "translate(" + x(d.title) + ",0)"; });

                    var drawTime = -1;
                    var colDuration = drawingDuration/data.length;
                    col.selectAll("rect")
                        .data(function(d) { return d.vulns; })
                        .enter().append("rect")
                        .attr("id", function(d){return d.graphId})
                        .attr("class", "bar")
                        .attr("width", 0)
                        .attr("y", function(d) { return y(d.y1); })
                        .attr("height", function(d) { return y(d.y0) - y(d.y1); })
                        .style("fill", function(d) { return d.fillColor; })
                        .on('mouseover', tip.show)
                        .on('mouseout', tip.hide)
                        .on('click', function(d) {
                            tip.hide();
                            threadFixModalService.showVulnsModal(vulnSearchParameterService.createFilterCriteria(d, scope.label), scope.label.teamId || scope.label.appId);
                        })
                        .transition()
                        .attr("width", x.rangeBand())
                        .duration(colDuration)
                        .delay(function(d) {
                            if (d.y0 === 0)
                                drawTime++;
                            return colDuration*drawTime; }) ;

                };
                ;
            }
        }
    }]);

// Top Applications Summary report
d3ThreadfixModule.directive('d3Hbars', ['$window', '$timeout', 'd3', 'd3Service', 'reportConstants', 'reportUtilities', 'threadFixModalService', 'vulnSearchParameterService', 'reportExporter',
    function($window, $timeout, d3, d3Service, reportConstants, reportUtilities, threadFixModalService, vulnSearchParameterService, reportExporter) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                width: '@',
                height: '@',
                margin: '=',
                exportReportId: '='
            }
            ,
            link: function(scope, ele) {

                var margin = scope.margin,
                    width = scope.width - margin.left - margin.right,
                    height = scope.height - margin.top - margin.bottom;

                var x = d3Service.getScaleLinearRange(d3, [0, width]);

                var y = d3Service.getScaleOrdinalRangeBand(d3, [0, height], .1);

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);

                var xAxis = d3Service.getAxis(d3, x, "bottom");

                var yAxis = d3Service.getAxis(d3, y, "left")
                        .tickFormat(function(d){
                            var arr = d.split("/");
                            d = (arr.length >1) ? arr[1] : d;
                            if (d && d.length > 8)
                                return d.substring(0,8) + "...";
                            else
                                return d;
                        })
                    ;

                var svg = d3Service.getSvg(d3, ele[0], width + margin.left + margin.right, height + margin.top + margin.bottom);

                var tip = d3Service.getTip(d3, 'd3-tip', [-10, 0], 'horizontalBarTip')
                    .html(function(d) {
                        return "<strong>" + d.tip + ":</strong> <span style='color:red'>" + (d.y1 - d.y0) + "</span>";
                    });
                svg.call(tip);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    svg.selectAll('*').remove();
                    svg.append("g").attr("id","topAppChart");

                    var svg1 = d3.select("#topAppChart")
                        .append("svg")
                        .attr("width", scope.width)
                        .attr("height", scope.height)
                        .append("g")
                        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                    if (!data || data.length < 1) return;

                    if (scope.label && (scope.label.teams || scope.label.apps))
                        reportUtilities.drawTitle(svg1, scope.width, scope.label, "Most Vulnerable Applications", -30);

                    barGraphData(d3, data, color, false, scope.label, reportConstants);

                    y.domain(data.map(function(d) { return d.title; }));
                    x.domain([0, d3.max(data, function(d) { return d.total; })]);

                    svg1.append("g")
                        .attr("class", "y axis")
                        .attr("transform", "translate(0," + height + ")")
                        .call(xAxis);

                    svg1.append("g")
                        .attr("class", "x axis")
                        .call(yAxis);

                    var col = svg1.selectAll(".rect")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "g")
                        .attr("transform", function(d) { return "translate(0," + y(d.title) + ")"; });

                    var drawTime = -1;
                    var rowDuration = drawingDuration/data.length;

                    col.selectAll("rect")
                        .data(function(d) { return d.vulns; })
                        .enter().append("rect")
                        .attr("id", function(d){return d.graphId})
                        .attr("class", "bar pointer")
                        .attr("height", 0)
                        .attr("x", function(d) { return x(d.y0); })
                        .attr("width", function(d) { return x(d.y1) - x(d.y0); })
                        .style("fill", function(d) { return d.fillColor; })
                        .on('mouseover', tip.show)
                        .on('mouseout', tip.hide)
                        .on('click', function(d) {
                            tip.hide();
                            threadFixModalService.showVulnsModal(vulnSearchParameterService.createFilterCriteria(d, scope.label), scope.label.teamId || scope.label.appId);
                        })
                        .transition()
                        .attr("height", y.rangeBand())
                        .duration(rowDuration)
                        .delay(function(d) {
                            if (d.y0 === 0)
                                drawTime++;
                            return rowDuration*drawTime; })
                    ;

                };

                scope.$watch('exportReportId', function() {
                    scope.export();
                });

                scope.export = function(){
                    if (scope.exportReportId==10) {
                        var teamsName = (scope.label.teams) ? "_" + scope.label.teams : "";
                        var appsName = (scope.label.apps) ? "_" + scope.label.apps : "";
                        reportExporter.exportPDFSvg(d3, svg, scope.width, scope.height,
                                "TopVulnerableApplications" + teamsName + appsName);
                    }
                };

            }
        }
    }]);

// Donut
d3ThreadfixModule.directive('d3Donut', ['$window', '$timeout', 'd3', 'd3donut', 'd3Service', 'reportConstants',
    function($window, $timeout, d3, d3donut, d3Service, reportConstants) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: "@"
            }
            ,
            link: function(scope, ele) {

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);

                    if (!data)
                        return;

                    color.domain(reportConstants.vulnTypeList);

                    var pieDim ={w:260, h: 200};

                    var svg = d3Service.getSvg(d3, ele[0], pieDim.w, pieDim.h);

                    svg.append("g").attr("id",scope.label);

                    d3donut.draw2D(scope.label, getData(), pieDim.h, pieDim.w, pieDim.w/2, pieDim.h/2, Math.min(pieDim.w, pieDim.h) / 2, true, null);

                    function getData(){
                        var d = data[0];
                        return color.domain().map(function(vulnType) {
                            return {tip:vulnType, value:d[vulnType], fillColor:color(vulnType), severity: vulnType, teamId: d.teamId, teamName: d.teamName};});
                    }

                };
                ;
            }
        }
    }]);


/*** UTILITY FUNCTIONS ***/

function barGraphData(d3, data, color, isLeftReport, label, reportConstants) {
    var keys = d3.keys(data[0]).filter(function(key) { return key; });
    var topVulnsReport = false;

    if (keys.indexOf("count") > -1) {
        color.domain(topVulnMapKeyword);
        topVulnsReport = true;
    }
    else
        color.domain(reportConstants.vulnTypeList);

    data.forEach(function(d, index) {
        var y0 = 0;
        d.vulns = color.domain().map(function(key) {
            //If it is top vulnerability report, then pick color of "High"
            var _key = (topVulnsReport) ? "High" : key;
            var tip = (topVulnsReport) ? d.name + " (CWE " + d.displayId + ")" : key;
            return {
                time: (isLeftReport) ? getTime(data.length-index) : undefined,
                fillColor: color(_key),
                tip : tip,
                y0: y0,
                y1: y0 += +d[key],
                teamId: (label && label.teamId) ? label.teamId : d.teamId,
                teamName: d.teamName,
                appId: (label && label.appId) ? label.appId : d.appId,
                appName: d.appName,
                severity: (topVulnsReport) ? undefined : key,
                graphId: d.teamName + d.appName + ((topVulnsReport)? "CWE" + d.displayId : tip) + "Bar"
            };
        });
        d.total = d.vulns[d.vulns.length - 1].y1;
    });
}

function getTime(index) {
    return new Date(currentYear, currentMonth - index + 2, 0);
}

var topVulnMapKeyword = ["count"];
var currentDate = new Date();
var currentYear = currentDate.getFullYear();
var currentMonth = currentDate.getMonth();
var drawingDuration = 500;
