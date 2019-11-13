package com.codegym.inote.service;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Trash;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface RecycleBinService extends GeneralService<Trash> {
    Page<Trash> findAllByUser(User user, Pageable pageable);

    Trash addNoteToRecycleBin(Note note);
}
