package com.navis.security.repository;

import com.navis.security.model.TestObject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TestObjectRepository extends JpaRepository<TestObject, Long> {
}

