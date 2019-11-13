package com.codegym.inote.controller;

import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import com.codegym.inote.service.NoteTypeService;
import com.codegym.inote.service.StackService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/stack")
public class StackController {

    private static final String STACK = "stack";
    private static final String ERROR_404 = "/error-404";

    @Autowired
    private StackService stackService;

    @Autowired
    private NoteTypeService noteTypeService;

    @Autowired
    private UserService userService;

    @ModelAttribute("user")
    public User user() {
        return userService.getCurrentUser();
    }

    @GetMapping("/stacks/{id}")
    public ModelAndView showAllStack(@PathVariable Long id, Pageable pageable) {
        Page<Stack> stacks = stackService.findAllByUser(userService.getCurrentUser(), pageable);

        ModelAndView modelAndView = new ModelAndView("/stack/list");
        modelAndView.addObject("stacks", stacks);
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @GetMapping("/create/{id}")
    public ModelAndView showCreateForm(@PathVariable Long id) {
        ModelAndView modelAndView = new ModelAndView("/stack/create");
        modelAndView.addObject(STACK, new Stack());
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }

    @PostMapping("/create")
    public ModelAndView saveStack(@ModelAttribute Stack stack) {
        stack.setUser(userService.getCurrentUser());
        stackService.save(stack);
        ModelAndView modelAndView = new ModelAndView("/stack/create");
        modelAndView.addObject(STACK, new Stack());
        modelAndView.addObject("message", "Created!");
        return modelAndView;
    }

    @GetMapping("/edit/{id}/{userId}")
    public ModelAndView showEditForm(@PathVariable Long id,@PathVariable Long userId) {
        Stack stack = stackService.findById(id);
        if (stack != null) {
            ModelAndView modelAndView = new ModelAndView("/stack/edit");
            modelAndView.addObject(STACK, stack);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/edit")
    public ModelAndView updateStack(@ModelAttribute Stack stack) {
        stack.setUser(userService.getCurrentUser());
        stackService.save(stack);
        ModelAndView modelAndView = new ModelAndView("/stack/edit");
        modelAndView.addObject(STACK, stack);
        modelAndView.addObject("message", "Updated!");
        return modelAndView;
    }

    @GetMapping("/delete/{id}/{userId}")
    public ModelAndView showDeleteForm(@PathVariable Long id,@PathVariable Long userId) {
        Stack stack = stackService.findById(id);
        if (stack != null) {
            ModelAndView modelAndView = new ModelAndView("/stack/delete");
            modelAndView.addObject(STACK, stack);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/delete")
    public String deleteTag(@ModelAttribute Stack stack, Pageable pageable) {
        Stack currentStack = stackService.findById(stack.getId());
        Page<NoteType> noteTypes = noteTypeService.findNoteTypeByStack(currentStack, pageable);
        for (NoteType noteType : noteTypes
        ) {
            noteType.setStack(null);
            noteTypeService.save(noteType);
        }
        stackService.remove(stack.getId());
        return "redirect:/stack/stacks/"+ userService.getCurrentUser().getId();
    }

    @GetMapping("/view/{id}/{userId}")
    public ModelAndView viewTag(@PathVariable Long id,@PathVariable Long userId, Pageable pageable) {
        Stack stack = stackService.findById(id);
        if (stack == null) {
            return new ModelAndView(ERROR_404);
        }
        Page<NoteType> noteTypes = noteTypeService.findNoteTypeByStack(stack, pageable);
        ModelAndView modelAndView = new ModelAndView("/stack/view");
        modelAndView.addObject(STACK, stack);
        modelAndView.addObject("user", userService.getCurrentUser());
        modelAndView.addObject("noteTypes", noteTypes);
        return modelAndView;
    }
}
