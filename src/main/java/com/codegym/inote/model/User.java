package com.codegym.inote.model;


import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "user")
public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    @NotEmpty(message = "username must be fill")
    @Size(min = 6, max = 15, message = "username length must be between 6 and 15")
    private String username;

    @Column(nullable = false, unique = true)
    @NotEmpty(message = "email must be fill")
    @Email(message = "Incorrect form")
    private String email;

    @NotEmpty(message = "password must be fill")
    @Size(min = 6, message = "password length must be at least 6 characters")
    private String password;

    @NotEmpty(message = "confirm password must be fill")
    @Size(min = 6, message = "password length must be at least 6 characters")
    private String confirmPassword;

    @NotEmpty(message = "phoneNumber must be full")
    @Size(min = 9, max = 10, message = "your phoneNumber must be 9 or 10 digit")
    @Pattern(regexp = "^[0-9]*$", message ="input only number in this field")
    private String phoneNumber;

    @Column(name = "enabled", nullable = false, columnDefinition = "TINYINT(1)")
    private boolean enabled;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<Role> roles = new HashSet<>();

    @JsonIgnore
    @OneToMany(targetEntity = Note.class, fetch = FetchType.EAGER)
    private Set<Note> notes;

    @JsonIgnore
    @OneToMany(targetEntity = NoteType.class, fetch = FetchType.EAGER)
    private Set<NoteType> noteTypes;

    @JsonIgnore
    @OneToMany(targetEntity = Stack.class, fetch = FetchType.EAGER)
    private Set<Stack> stacks;

    @JsonIgnore
    @OneToMany(targetEntity = Tag.class, fetch = FetchType.EAGER)
    private Set<Stack> tags;

    @JsonIgnore
    @OneToMany(targetEntity = Trash.class, fetch = FetchType.EAGER)
    private Set<Trash> trashes;

    @OneToOne(mappedBy = "user")
    private ConfirmationToken token;

    public Set<Trash> getTrashes() {
        return trashes;
    }

    public void setTrashes(Set<Trash> trashes) {
        this.trashes = trashes;
    }

    public Set<Stack> getTags() {
        return tags;
    }

    public void setTags(Set<Stack> tags) {
        this.tags = tags;
    }

    public Set<Stack> getStacks() {
        return stacks;
    }

    public void setStacks(Set<Stack> stacks) {
        this.stacks = stacks;
    }

    public Set<NoteType> getNoteTypes() {
        return noteTypes;
    }

    public void setNoteTypes(Set<NoteType> noteTypes) {
        this.noteTypes = noteTypes;
    }

    public Set<Note> getNotes() {
        return notes;
    }

    public void setNotes(Set<Note> notes) {
        this.notes = notes;
    }

    public User() {
    }

    public User(String username, String email,String phoneNumber , String password,
                String confirmPassword, Set<Role> roles) {
        this.username = username;
        this.password = password;
        this.confirmPassword = confirmPassword;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.enabled = false;
        this.roles = roles;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public ConfirmationToken getToken() {
        return token;
    }

    public void setToken(ConfirmationToken token) {
        this.token = token;
    }

    @Transient
    public List<GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (Role currentRole : this.roles) {
            authorities.add(new SimpleGrantedAuthority(currentRole.getName()));
        }
        return authorities;
    }


}
