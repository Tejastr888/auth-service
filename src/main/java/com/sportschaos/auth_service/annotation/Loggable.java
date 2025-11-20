package com.sportschaos.auth_service.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Loggable {
    String value() default "";
    boolean logParameters() default true;
    boolean logResult() default true;
    boolean logExecutionTime() default true;
}