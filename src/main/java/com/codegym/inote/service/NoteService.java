package com.codegym.inote.service;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Tag;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface NoteService extends GeneralService<Note> {
    Page<Note> findAllByNoteType(NoteType noteType, Pageable pageable);

    Page<Note> findNoteByTitleContains(String title, Pageable pageable);

    Page<Note> findAllByTags(Tag tag, Pageable pageable);

    Page<Note> findAllByUser(User user, Pageable pageable);
}
