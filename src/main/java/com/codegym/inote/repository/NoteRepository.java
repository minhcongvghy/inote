package com.codegym.inote.repository;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Tag;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface NoteRepository extends PagingAndSortingRepository<Note, Long> {
    Page<Note> findAllByNoteType(NoteType noteType, Pageable pageable);

    Page<Note> findNoteByTitleContains(String title, Pageable pageable);

    Page<Note> findAllByTags(Tag tag, Pageable pageable);

    Page<Note> findAllByUser(User user, Pageable pageable);
}
