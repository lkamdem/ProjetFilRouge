package com.epita.filrouge;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan(basePackages = "com.epita.filrouge")
@EnableJpaRepositories
public class SpringBootApplicationTest {

}
