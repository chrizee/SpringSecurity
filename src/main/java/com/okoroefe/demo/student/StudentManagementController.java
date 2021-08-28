package com.okoroefe.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/student")
public class StudentManagementController {

    private final List<Student> Students = Arrays.asList(
            new Student(1, "Efe"),
            new Student(2, "Chris"),
            new Student(3, "Okoro")

    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> get() {
        return Students;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @PutMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("id") int id, @RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("id") int id) {
        System.out.println(id);
    }

}
