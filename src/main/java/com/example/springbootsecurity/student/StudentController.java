package com.example.springbootsecurity.student;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static List<Student>STUDENTS= Arrays
            .asList(
                    new Student(1,"hamza "),
                    new Student(2,"ahmed "),
                    new Student(3,"amir ")
            );
@GetMapping("/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
return STUDENTS.stream()
        .filter(student -> studentId.equals(student.getStudentId()))
        .findFirst()
        .orElseThrow(()->new IllegalStateException("There is no student with this ID: "+studentId));

    }
}
