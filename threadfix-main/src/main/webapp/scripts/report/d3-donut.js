angular.module('threadfix')
    .factory('d3donut',['d3', 'threadFixModalService', 'vulnSearchParameterService', function(d3, threadFixModalService, vulnSearchParameterService){

        var Donut={};

        var tip = d3.tip()
            .attr('class', 'd3-tip')
            .attr("id", "pointInTimeTip")
            .offset([-10, 0])
            .html(function(d) {
                return "<strong>" + d.data.tip + ":</strong> <span style='color:red'>" + d.value + "</span> <span>(" + getPercent(d) + ")</span>";
            });

        function pieTop(d, rx, ry, ir ){
            if(d.endAngle - d.startAngle == 0 ) return "M 0 0";
            var sx = rx*Math.cos(d.startAngle),
                sy = ry*Math.sin(d.startAngle),
                ex = rx*Math.cos(d.endAngle),
                ey = ry*Math.sin(d.endAngle);

            var ret =[];
            ret.push("M",sx,sy,"A",rx,ry,"0",(d.endAngle-d.startAngle > Math.PI? 1: 0),"1",ex,ey,"L",ir*ex,ir*ey);
            ret.push("A",ir*rx,ir*ry,"0",(d.endAngle-d.startAngle > Math.PI? 1: 0), "0",ir*sx,ir*sy,"z");
            return ret.join(" ");
        }

        function pieOuter(d, rx, ry, h ){
            var startAngle = (d.startAngle > Math.PI ? Math.PI : d.startAngle);
            var endAngle = (d.endAngle > Math.PI ? Math.PI : d.endAngle);

            var sx = rx*Math.cos(startAngle),
                sy = ry*Math.sin(startAngle),
                ex = rx*Math.cos(endAngle),
                ey = ry*Math.sin(endAngle);

            var ret =[];
            ret.push("M",sx,h+sy,"A",rx,ry,"0 0 1",ex,h+ey,"L",ex,ey,"A",rx,ry,"0 0 0",sx,sy,"z");
            return ret.join(" ");
        }

        function pieInner(d, rx, ry, h, ir ){
            var startAngle = (d.startAngle < Math.PI ? Math.PI : d.startAngle);
            var endAngle = (d.endAngle < Math.PI ? Math.PI : d.endAngle);

            var sx = ir*rx*Math.cos(startAngle),
                sy = ir*ry*Math.sin(startAngle),
                ex = ir*rx*Math.cos(endAngle),
                ey = ir*ry*Math.sin(endAngle);

            var ret =[];
            ret.push("M",sx, sy,"A",ir*rx,ir*ry,"0 0 1",ex,ey, "L",ex,h+ey,"A",ir*rx, ir*ry,"0 0 0",sx,h+sy,"z");
            return ret.join(" ");
        }

        function getPercent(d){
            return Math.round(1000*(d.endAngle-d.startAngle)/(Math.PI*2))/10+'%';
        }

        Donut.transition = function(id, data, rx, ry, h, ir){
            function arcTweenInner(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieInner(i(t), rx+0.5, ry+0.5, h, ir);  };
            }
            function arcTweenTop(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieTop(i(t), rx, ry, ir);  };
            }
            function arcTweenOuter(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieOuter(i(t), rx-.5, ry-.5, h);  };
            }
            function textTweenX(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return 0.6*rx*Math.cos(0.5*(i(t).startAngle+i(t).endAngle));  };
            }
            function textTweenY(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return 0.6*rx*Math.sin(0.5*(i(t).startAngle+i(t).endAngle));  };
            }

            var _data = d3.layout.pie().sort(null).value(function(d) {return d.value;})(data);

            d3.select("#"+id).selectAll(".innerSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenInner);

            d3.select("#"+id).selectAll(".topSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenTop);

            d3.select("#"+id).selectAll(".outerSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenOuter);

            d3.select("#"+id).selectAll(".percent").data(_data).transition().duration(750)
                .attrTween("x",textTweenX).attrTween("y",textTweenY).text(getPercent);
        }

        Donut.draw3D=function(id, data, x /*center x*/, y/*center y*/,
                              rx/*radius x*/, ry/*radius y*/, h/*height*/, ir/*inner radius*/){

            var _data = d3.layout.pie().sort(null).value(function(d) {return d.value;})(data);

            var svg = d3.select("#"+id).append("g").attr("transform", "translate(" + x + "," + y + ")");

            /* ------- TIP -------*/
            var tip = d3.tip()
                .attr('class', 'd3-tip')
                .offset([-10, 0])
                .html(function(d) {
                    return "<strong>" + d.data.tip + ":</strong> <span style='color:red'>" + d.value + "</span> <span>(" + getPercent(d) + ")</span>";
                });
            svg.call(tip);

            var slices = svg.append("g")
                .attr("class", "slices");

            slices.selectAll(".innerSlice").data(_data).enter().append("path").attr("class", "innerSlice")
                .style("fill", function(d) { return d3.hsl(d.data.fillColor).darker(0.7); })
                .attr("d",function(d){ return pieInner(d, rx+0.5,ry+0.5, h, ir);})
                .each(function(d){this._current=d;})
                .on('mouseover', tip.show)
                .on('mouseout', tip.hide)
            ;

            slices.selectAll(".topSlice").data(_data).enter().append("path").attr("class", "topSlice")
                .style("fill", function(d) { return d.data.fillColor; })
                .style("stroke", function(d) { return d.data.fillColor; })
                .attr("d",function(d){ return pieTop(d, rx, ry, ir);})
                .each(function(d){this._current=d;})
                .on('mouseover', tip.show)
                .on('mouseout', tip.hide)
            ;

            slices.selectAll(".outerSlice").data(_data).enter().append("path").attr("class", "outerSlice")
                .style("fill", function(d) { return d3.hsl(d.data.fillColor).darker(0.7); })
                .attr("d",function(d){ return pieOuter(d, rx-.5,ry-.5, h);})
                .each(function(d){this._current=d;})
                .on('mouseover', tip.show)
                .on('mouseout', tip.hide)
            ;
        }

        Donut.draw2D=function(id, data, height/*height*/, width/*width*/, x, y, rs/*radius*/, isNavigate, label){
            var arc = d3.svg.arc()
                .outerRadius(rs - 10)
                .innerRadius(0);

            var _data = d3.layout.pie().sort(null).value(function(d) {return d.value;})(data);

            var svg = d3.select("#"+id)
                .append("svg")
                .attr("width", width)
                .attr("height", height)
                .append("g")
                .attr("transform", "translate(" + x + "," + y + ")");

            svg.selectAll('*').remove();

            svg.call(tip);

            var durationEachAngle = 500/(2*Math.PI);

            var slices = svg.append("g")
                .attr("class", "slices")

            slices.selectAll(".arc")
                .data(_data).enter()
                .append("g")
                .attr("class", "arc pointer")
                .attr("id", function(d){
                    var str = (d.data.teamName)? d.data.teamName : "pointInTime";
                    return str + d.data.severity + "Arc";
                })
                .append("path")
                .style("fill", function(d) { return d.data.fillColor; })
                .on('mouseover', tip.show)
                .on('mouseout', tip.hide)
                .on('click', function(d) {
                    tip.hide();
                    if (isNavigate){
                        if (!label)
                            label = {};
                        threadFixModalService.showVulnsModal(vulnSearchParameterService.createFilterCriteria(d.data, label), false);
                    }
                })
                .transition().delay(function(d, i) { return durationEachAngle * d.startAngle; })
                .duration(function(d){ return durationEachAngle * (d.endAngle-d.startAngle); })
                .attrTween('d', function(d) {
                    var i = d3.interpolate(d.startAngle, d.endAngle);
                    return function(t) {
                        d.endAngle = i(t);
                        return arc(d);
                    }
                })
            ;
        }

        return Donut;
    }]);