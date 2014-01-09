/**
 * For some reason this file didn't parse correctly with code as of 1/8/2013 so it's here as a test case.
 */
package code.spring;

import de.congrace.exp4j.Calculable;
import de.congrace.exp4j.ExpressionBuilder;
import de.congrace.exp4j.UnknownFunctionException;
import de.congrace.exp4j.UnparsableExpressionException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

@Controller
public class MathController {

    @RequestMapping(value = "/evaluate", method = RequestMethod.GET)
    @ResponseBody
    public Map<String, Object> evaluate(HttpServletRequest request) throws UnknownFunctionException, UnparsableExpressionException {
        String query = request.getParameter("query");

        Calculable calc = new ExpressionBuilder(query).build();

        return Collections.singletonMap(query, (Object) calc.calculate());
    }

}
