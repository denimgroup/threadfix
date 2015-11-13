var d3ThreadfixModule = angular.module('threadfix');

// Point in time
d3ThreadfixModule.directive('d3Pointintime', ['$window', '$timeout', 'd3', 'd3donut', 'reportExporter', 'd3Service', 'reportConstants', 'reportUtilities', 'customSeverityService',
    function($window, $timeout, d3, d3donut, reportExporter, d3Service, reportConstants, reportUtilities, customSeverityService) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                updateTree: '&',
                exportReportId: '='
            }
            ,
            link: function(scope, ele) {

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);
                var pieDim ={w:670, h: 350};
                var svg;

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                //scope.$watch('exportReportId', function() {
                //    scope.export();
                //}, true);

                scope.$watch('label', function(newVals) {
                    scope.render(scope.data);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    if (!data)
                        return;

                    color.domain(reportConstants.vulnTypeList);
                    svg = d3Service.getExistingSvg(d3, ele[0], pieDim.w, pieDim.h);
                    svg.selectAll('*').remove();
                    svg.attr("id", "pointInTimeGraph");

                    if (Object.keys(data).length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", pieDim.w/2)
                            .attr("y", 130)
                            .attr("class", "warning")
                            .text("Select fields to display")
                        return;
                    }

                    var id = "pointInTimeDonut";
                    svg.append("rect")
                        .attr("transform", "translate(0, 0)")
                        .attr("width", pieDim.w)
                        .attr("height", pieDim.h)
                        .attr("fill", "#ffffff")
                        .attr("strokeWidth", 0);

                    reportUtilities.drawTitle(svg, pieDim.w, scope.label, "Point in Time Report", 30);

                    svg.append("g").attr("id",id);

                    d3donut.draw2D(id, getData(), pieDim.h, pieDim.w, 150, 200 , 100, true, scope.label);

                    var tableData = [];
                    if (data[customSeverityService.getCustomSeverity('Critical')])
                        tableData.push(data[customSeverityService.getCustomSeverity('Critical')]);
                    if (data[customSeverityService.getCustomSeverity('High')])
                        tableData.push(data[customSeverityService.getCustomSeverity('High')]);
                    if (data[customSeverityService.getCustomSeverity('Medium')])
                        tableData.push(data[customSeverityService.getCustomSeverity('Medium')]);
                    if (data[customSeverityService.getCustomSeverity('Low')])
                        tableData.push(data[customSeverityService.getCustomSeverity('Low')]);
                    if (data[customSeverityService.getCustomSeverity('Info')])
                        tableData.push(data[customSeverityService.getCustomSeverity('Info')]);

                    var legend = svg.selectAll(".legend")
                        .data(tableData)
                        .enter().append("g")
                        .attr("class", "legend")
                        .attr("id", function(d){return "legend" + d.Severity;})
                        .attr("transform", function(d, i) { return "translate(300," + (150 + i * 20) + ")"; });

                    legend.append("rect")
                        .attr("x", 40)
                        .attr("width", 18)
                        .attr("height", 18)
                        .style("fill", function(d){return color(d.Severity)});

                    legend.append("text")
                        .attr("x", 64)
                        .attr("y", 9)
                        .attr("dy", ".70em")
                        .style("text-anchor", "start")
                        .text(function(d) {
                            return (d.Severity.length > 8 ? d.Severity.substring(0,8).concat("...") : d.Severity) ;
                        });

                    legend.append("text")
                        .attr("x", 120)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function(d) { return d.Count + "(" + d.Percentage + ")"; });

                    legend.append("text")
                        .attr("x", 200)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function(d) { return "Average Age: " + d.Avg_Age; });

                    function getData(){
                        var _data = [];
                        color.domain().map(function(vulnType) {
                            if (data[vulnType])
                                _data.push({tip:vulnType,
                                    value:data[vulnType]['Count'],
                                    fillColor:color(vulnType),
                                    severity: vulnType,
                                    genericSeverities: data.genericSeverities
                                });
                        });
                        return _data;
                    };
                };

                scope.export = function(){
                    if (scope.exportReportId && scope.exportReportId.id==2) {
                        var teamsName = (scope.label.teams) ? "_" + scope.label.teams : "";
                        var appsName = (scope.label.apps) ? "_" + scope.label.apps : "";
                        reportExporter.exportPDFSvg(d3, svg, pieDim.w, pieDim.h,
                                "PointInTime" + teamsName + appsName, scope.exportReportId.isPDF);
                    }
                };
            }
        }
    }]);
