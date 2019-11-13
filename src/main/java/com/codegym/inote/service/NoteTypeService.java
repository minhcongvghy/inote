package com.codegym.inote.service;

import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface NoteTypeService extends GeneralService<NoteType> {
    Page<NoteType> findNoteTypeByName(String name, Pageable pageable);

    Page<NoteType> findNoteTypeByStack(Stack stack, Pageable pageable);

    Page<NoteType> findAllByUser(User user, Pageable pageable);

}
