package com.codegym.inote.controller.restful;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Tag;
import com.codegym.inote.service.NoteService;
import com.codegym.inote.service.TagService;
import com.codegym.inote.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/restful")
public class TagRestController {
    @Autowired
    private TagService tagService;

    @Autowired
    private UserService userService;

    @Autowired
    private NoteService noteService;

    @GetMapping("/tags")
    public ResponseEntity<Page<Tag>> showAllTags(Pageable pageable) {
        Page<Tag> tags = tagService.findAllByUser(userService.getCurrentUser(), pageable);
        if (tags.getTotalElements() == 0) {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(tags, HttpStatus.OK);
    }

    @GetMapping("/tags/{id}")
    public ResponseEntity<Tag> getTag(@PathVariable Long id) {
        Tag tag = tagService.findById(id);
        if (tag == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(tag, HttpStatus.OK);
    }

    @PostMapping("/tags")
    public ResponseEntity<String> createTag(@RequestBody Tag tag) {
        tag.setUser(userService.getCurrentUser());
        tagService.save(tag);
        return new ResponseEntity<>("Created", HttpStatus.CREATED);
    }

    @PutMapping("/tags/{id}")
    public ResponseEntity<Tag> updateTag(@PathVariable Long id, @RequestBody Tag tag) {
        Tag currentTag = tagService.findById(id);
        if (currentTag == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        currentTag.setUser(tag.getUser());
        currentTag.setName(tag.getName());
        currentTag.setNotes(tag.getNotes());
        return new ResponseEntity<>(currentTag, HttpStatus.OK);
    }

    @DeleteMapping("/tags/{id}")
    public ResponseEntity<Tag> deleteTag(@PathVariable Long id, Pageable pageable) {
        Tag tag = tagService.findById(id);
        if (tag == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Page<Note> notes = noteService.findAllByTags(tag, pageable);
        for (Note note : notes
        ) {
            note.setTags(null);
            noteService.save(note);
        }
        tagService.remove(tag.getId());
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
