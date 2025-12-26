package com.zidtech.common.security.annotation;

import com.zidtech.common.security.config.SecurityFilterConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SecurityFilterConfiguration.class)
public @interface EnableJwtSecurity {
}
