package com.okoroefe.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/student")
public class StudentController {

    private final List<Student> Students = Arrays.asList(
            new Student(1, "Efe"),
            new Student(2, "Chris"),
            new Student(3, "Okoro")

    );
    @GetMapping(path = "{id}")
    public Student getStudent(@PathVariable("id") int id) {
        return Students.stream().filter(x -> x.getId() == id).findFirst()
                .orElseThrow(() -> new IllegalStateException("Student does not exist"));
    }
}
