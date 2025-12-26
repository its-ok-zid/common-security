package com.zidtech.common.security;

import com.zidtech.common.security.annotation.EnableJwtSecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableJwtSecurity
public class CommonSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(CommonSecurityApplication.class, args);
	}

}
