package com.codegym.inote.controller;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import com.codegym.inote.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Controller
@RequestMapping("/noteType")
public class NoteTypeController {

    private static final String NOTE_TYPE = "noteType";
    private static final String ERROR_404 = "/error-404";

    @Autowired
    private NoteTypeService noteTypeService;

    @Autowired
    private NoteService noteService;

    @Autowired
    private StackService stackService;

    @Autowired
    private UserService userService;

    @Autowired
    private RecycleBinService recycleBinService;

    @ModelAttribute("stacks")
    public Page<Stack> stacks(Pageable pageable) {
        return stackService.findAllByUser(userService.getCurrentUser(), pageable);
    }

    @ModelAttribute("user")
    public User user() {
        return userService.getCurrentUser();
    }

    @GetMapping("/noteTypeList/{id}")
    public ModelAndView showNoteTypeList(@PathVariable Long id, @RequestParam("search") Optional<String> search, Pageable pageable) {
        Page<NoteType> noteTypes;

        if (search.isPresent()) {
            noteTypes = noteTypeService.findNoteTypeByName(search.get(), pageable);
        } else {
            noteTypes = noteTypeService.findAllByUser(userService.getCurrentUser(), pageable);
        }
        ModelAndView modelAndView = new ModelAndView("/noteType/list");
        modelAndView.addObject("noteTypes", noteTypes);
        modelAndView.addObject("user", userService.getCurrentUser());

        return modelAndView;
    }

    @GetMapping("/create/{id}")
    public ModelAndView showCreateForm(@PathVariable Long id) {
        ModelAndView modelAndView = new ModelAndView("/noteType/create");
        modelAndView.addObject(NOTE_TYPE, new NoteType());
        return modelAndView;
    }

    @PostMapping("/create")
    public ModelAndView saveNoteType(@ModelAttribute NoteType noteType) {
        noteType.setUser(userService.getCurrentUser());
        noteTypeService.save(noteType);
        ModelAndView modelAndView = new ModelAndView("/noteType/create");
        modelAndView.addObject(NOTE_TYPE, new NoteType());
        modelAndView.addObject("message", "Created!");
        return modelAndView;
    }

    @GetMapping("/edit/{id}/{userId}")
    public ModelAndView showEditForm(@PathVariable Long userId, @PathVariable Long id) {
        NoteType noteType = noteTypeService.findById(id);
        if (noteType != null) {
            ModelAndView modelAndView = new ModelAndView("/noteType/edit");
            modelAndView.addObject(NOTE_TYPE, noteType);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/edit")
    public ModelAndView editNoteType(@ModelAttribute NoteType noteType) {
        noteType.setUser(userService.getCurrentUser());
        noteTypeService.save(noteType);

        ModelAndView modelAndView = new ModelAndView("/noteType/edit");
        modelAndView.addObject(NOTE_TYPE, noteType);
        modelAndView.addObject("message", "Updated!");
        return modelAndView;
    }

    @GetMapping("/delete/{id}/{userId}")
    public ModelAndView showDeleteForm(@PathVariable Long id, @PathVariable Long userId) {
        NoteType noteType = noteTypeService.findById(id);
        if (noteType != null) {
            ModelAndView modelAndView = new ModelAndView("/noteType/delete");
            modelAndView.addObject(NOTE_TYPE, noteType);
            modelAndView.addObject("user", userService.getCurrentUser());
            return modelAndView;
        }
        return new ModelAndView(ERROR_404);
    }

    @PostMapping("/delete")
    public String deleteNoteType(@ModelAttribute NoteType noteType, Pageable pageable) {
        NoteType currentNoteType = noteTypeService.findById(noteType.getId());
        Page<Note> notes = noteService.findAllByNoteType(currentNoteType, pageable);
        for (Note note : notes) {
            recycleBinService.addNoteToRecycleBin(note);
        }
        noteTypeService.remove(noteType.getId());
        return "redirect:/noteType/noteTypeList/"+ userService.getCurrentUser().getId();
    }

    @GetMapping("/view/{id}/{userId}")
    public ModelAndView viewNoteType(@PathVariable Long id, @PathVariable Long userId, Pageable pageable) {
        NoteType noteType = noteTypeService.findById(id);
        if (noteType == null) {
            return new ModelAndView(ERROR_404);
        }
        Page<Note> notes = noteService.findAllByNoteType(noteType, pageable);
        ModelAndView modelAndView = new ModelAndView("/noteType/view");
        modelAndView.addObject(NOTE_TYPE, noteType);
        modelAndView.addObject("notes", notes);
        modelAndView.addObject("user", userService.getCurrentUser());
        return modelAndView;
    }
}
