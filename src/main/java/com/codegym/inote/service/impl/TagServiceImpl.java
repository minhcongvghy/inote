package com.codegym.inote.service.impl;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Tag;
import com.codegym.inote.model.User;
import com.codegym.inote.repository.TagRepository;
import com.codegym.inote.service.TagService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public class TagServiceImpl implements TagService {

    @Autowired
    private TagRepository tagRepository;

    @Override
    public Page<Tag> findAll(Pageable pageable) {
        return tagRepository.findAll(pageable);
    }

    @Override
    public Tag findById(Long id) {
        return tagRepository.findOne(id);
    }

    @Override
    public void save(Tag model) {
        tagRepository.save(model);
    }

    @Override
    public void remove(Long id) {
        tagRepository.delete(id);
    }

    @Override
    public Iterable<Tag> findAllByNotes(Note note) {
        return tagRepository.findAllByNotes(note);
    }

    @Override
    public Page<Tag> findTagByName(String name, Pageable pageable) {
        return tagRepository.findTagByName(name, pageable);
    }

    @Override
    public Page<Tag> findAllByUser(User user, Pageable pageable) {
        return tagRepository.findAllByUser(user, pageable);
    }
}
