var d3ThreadfixModule = angular.module('d3threadfix', ['d3']);

// Months Summary report
d3ThreadfixModule.directive('d3Bars', ['$window', '$timeout', 'd3',
    function($window, $timeout, d3) {
        return {
            restrict: 'EA',
            scope: {
                data: '='
//                ,
//                label: '@'
//                ,
//                onClick: '&'
            }
            ,
            link: function(scope, ele, attrs) {
//                d3Service.d3().then(function(d3) {

                var renderTimeout;
                var margin = {top: 20, right: 20, bottom: 30, left: 40},
                    width = 422 - margin.left - margin.right,
                    height = 250 - margin.top - margin.bottom;

                var x = d3.scale.ordinal()
                    .rangeRoundBands([0, width], .1);

                var y = d3.scale.linear()
                    .rangeRound([height, 0]);

                var color = d3.scale.ordinal()
                    .range(["#98abc5", "#8a89a6", "#7b6888", "#6b486b", "#a05d56"]);

                var xAxis = d3.svg.axis()
                    .scale(x)
                    .orient("bottom");

                var yAxis = d3.svg.axis()
                    .scale(y)
                    .orient("left")
                    .tickFormat(d3.format(".2s"));

                var svg =  d3.select(ele[0]).append("svg")
                    .attr("width", width + margin.left + margin.right)
                    .attr("height", height + margin.top + margin.bottom)
                    .append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                var tip = d3.tip()
                    .attr('class', 'd3-tip')
                    .offset([-10, 0])
                    .html(function(d) {
                        return "<strong>" + d.vulnTypeDisplay + ":</strong> <span style='color:red'>" + (d.y1 - d.y0) + "</span>";
                    });
                svg.call(tip);

                $window.onresize = function() {
                    scope.$apply();
                };

                scope.$watch(function() {
                    return angular.element($window)[0].innerWidth;
                }, function() {
                    scope.render(scope.data);
                });

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    svg.selectAll('*').remove();

                    if (!data || data.length < 1) return;

                    var keys = d3.keys(data[0]).filter(function(key) { return key !== "importTime"; });
                    keys.sort(function(a, b) { return a.localeCompare(b); });

                    color.domain(keys);

                    data.forEach(function(d) {
                        var y0 = 0;
                        d.vulns = color.domain().map(function(vulnType) {
                            return {
                                vulnType: vulnType,
                                vulnTypeDisplay: vulnType.split("-").length>2 ? vulnType.split("-")[1] : vulnType,
                                y0: y0,
                                y1: y0 += +d[vulnType]
                            };
                        });
                        d.total = d.vulns[d.vulns.length - 1].y1;
                    });

                    x.domain(data.map(function(d) { return d.importTime; }));
                    y.domain([0, d3.max(data, function(d) { return d.total; })]);

                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + height + ")")
                        .call(xAxis);

                    svg.append("g")
                        .attr("class", "y axis")
                        .call(yAxis)
                        .append("text")
                        .attr("transform", "rotate(-90)")
                        .attr("y", 6)
                        .attr("dy", ".71em")
                        .style("text-anchor", "end");

                    var state = svg.selectAll(".importTime")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "g")
                        .attr("transform", function(d) { return "translate(" + x(d.importTime) + ",0)"; });

                    state.selectAll("rect")
                        .data(function(d) { return d.vulns; })
                        .enter().append("rect")
                        .attr("class", "bar")
                        .attr("width", x.rangeBand())
                        .attr("y", function(d) { return y(d.y1); })
                        .attr("height", function(d) { return y(d.y0) - y(d.y1); })
                        .style("fill", function(d) { return color(d.vulnType); })
                        .on('mouseover', tip.show)
                        .on('mouseout', tip.hide)
                    ;

//                    var legend = svg.selectAll(".legend")
//                        .data(color.domain().slice().reverse())
//                        .enter().append("g")
//                        .attr("class", "legend")
//                        .attr("transform", function(d, i) { return "translate(0," + i * 20 + ")"; });
//
//                    legend.append("rect")
//                        .attr("x", width - 18)
//                        .attr("width", 18)
//                        .attr("height", 18)
//                        .style("fill", color);
//
//                    legend.append("text")
//                        .attr("x", width - 24)
//                        .attr("y", 9)
//                        .attr("dy", ".35em")
//                        .style("text-anchor", "end")
//                        .text(function(d) { return d; });

//                    var legend = svg.selectAll(".legend")
//                        .data(color.domain().slice().reverse())
//                        .enter().append("g")
//                        .attr("class", "legend")
////                        .attr("transform", function(d, i) { return "translate(0," + i * 20 + ")"; });
//                        .attr("transform", function(d, i) { return "translate(" +  i * 70 + ",0)"; });
//
//                    legend.append("rect")
//                        .attr("y", height+20)
//                        .attr("width", 10)
//                        .attr("height", 10)
//                        .style("fill", color);
//
//                    legend.append("text")
//                        .attr("x", 7)
//                        .attr("y", height+30)
//                        .attr("dx", ".35em")
////                        .style("text-anchor", "end")
//                        .text(function(d) { return d.split("-").length>2 ? d.split("-")[1] : d; });
                };
                ;
            }
        }
    }]);