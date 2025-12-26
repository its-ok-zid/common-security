package com.zidtech.common.security.annotation;

import com.zidtech.common.security.config.SecurityFilterConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SecurityFilterConfiguration.class)
public @interface EnableJwtSecurity {
}
