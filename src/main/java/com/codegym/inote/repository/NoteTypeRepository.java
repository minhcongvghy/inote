package com.codegym.inote.repository;

import com.codegym.inote.model.NoteType;
import com.codegym.inote.model.Stack;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface NoteTypeRepository extends PagingAndSortingRepository<NoteType, Long> {
    Page<NoteType> findNoteTypeByName(String name, Pageable pageable);

    Page<NoteType> findNoteTypeByStack(Stack stack, Pageable pageable);

    Page<NoteType> findAllByUser(User user, Pageable pageable);
}
