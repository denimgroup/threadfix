////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package code.spring;

import it.redoddity.mvc.models.Comment;
import it.redoddity.mvc.services.PostService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/blog/{postId}/comment")
public class CommentController {
    @Autowired
    PostService postService;

    @RequestMapping(method = RequestMethod.GET, produces = {"application/json"})
    @ResponseStatus(HttpStatus.OK)
    public @ResponseBody List<Comment> comments(@PathVariable Long postId) throws IOException {
        return postService.find(postId).getComments();
    }

    @RequestMapping(method = RequestMethod.POST, produces = {"text/html"})
    public String commentWithView(@PathVariable Long postId, @Valid Comment comment, BindingResult result, ModelMap model) throws IOException {
        if(!result.hasErrors()) {
            postService.addComment(postId, comment);
            return "redirect:/blog/"+ postId;
        } else {
            model.addAttribute("post", postService.find(postId));
            model.addAttribute("errors", result);
            return "post";
        }
    }

    @RequestMapping(method = RequestMethod.POST, produces = {"application/json"})
    @ResponseStatus(HttpStatus.CREATED)
    public Comment comment(@PathVariable Long postId, @Valid Comment comment, BindingResult result, HttpServletResponse response) throws IOException {
        if(!result.hasErrors()) {
            return postService.addComment(postId, comment);
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return null;
        }
    }
}
