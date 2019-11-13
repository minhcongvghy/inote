package com.codegym.inote.repository;

import com.codegym.inote.model.Note;
import com.codegym.inote.model.Tag;
import com.codegym.inote.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface TagRepository extends PagingAndSortingRepository<Tag, Long> {
    Iterable<Tag> findAllByNotes(Note note);

    Page<Tag> findTagByName(String name, Pageable pageable);

    Page<Tag> findAllByUser(User user, Pageable pageable);
}
