package com.codegym.inote.controller.restful;

import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.service.NoteTypeService;
import com.codegym.inote.service.StackService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/restful")
public class StackRestController {
    @Autowired
    private StackService stackService;

    @Autowired
    private NoteTypeService noteTypeService;

    @Autowired
    private UserService userService;

    @GetMapping("/stacks")
    public ResponseEntity<Page<Stack>> showAllStacks(Pageable pageable) {
        Page<Stack> stacks = stackService.findAllByUser(userService.getCurrentUser(), pageable);
        if (stacks.getTotalElements() == 0) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(stacks, HttpStatus.OK);
    }

    @GetMapping("/stacks/{id}")
    public ResponseEntity<Stack> getStack(@PathVariable Long id) {
        Stack stack = stackService.findById(id);
        if (stack == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(stack, HttpStatus.OK);
    }

    @PostMapping("/stacks")
    public ResponseEntity<String> createStack(@RequestBody Stack stack) {
        stack.setUser(userService.getCurrentUser());
        stackService.save(stack);
        return new ResponseEntity<>("Created!", HttpStatus.CREATED);
    }

    @PutMapping("/stacks/{id}")
    public ResponseEntity<Stack> updateStack(@PathVariable Long id, @RequestBody Stack stack) {
        Stack currentStack = stackService.findById(id);
        if (currentStack == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        currentStack.setName(stack.getName());
        currentStack.setNoteTypes(stack.getNoteTypes());
        currentStack.setUser(stack.getUser());
        return new ResponseEntity<>(currentStack, HttpStatus.OK);
    }

    @DeleteMapping("/stacks/{id}")
    public ResponseEntity<Stack> deleteStack(@PathVariable Long id, Pageable pageable) {
        Stack stack = stackService.findById(id);
        if (stack == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Page<NoteType> noteTypes = noteTypeService.findNoteTypeByStack(stack, pageable);
        for (NoteType noteType : noteTypes
        ) {
            noteType.setStack(null);
            noteTypeService.save(noteType);
        }
        stackService.remove(stack.getId());
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
