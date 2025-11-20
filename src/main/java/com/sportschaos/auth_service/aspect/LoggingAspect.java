package com.sportschaos.auth_service.aspect;



import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;

import java.util.Arrays;
import java.util.stream.Collectors;

@Aspect
@Component
@Slf4j
public class LoggingAspect {

    @Around("@annotation(com.sportschaos.auth_service.annotation.Loggable) || " +
            "execution(* com.sportschaos.auth_service.service.*.*(..))")
    public Object logMethodExecution(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        String className = methodSignature.getDeclaringType().getSimpleName();
        String methodName = methodSignature.getName();
        String fullMethodName = className + "." + methodName;

        // Log method entry with parameters
        logMethodEntry(fullMethodName, joinPoint.getArgs());

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        try {
            Object result = joinPoint.proceed();
            stopWatch.stop();

            // Log method exit with result and execution time
            logMethodExit(fullMethodName, result, stopWatch.getTotalTimeMillis());
            return result;

        } catch (Exception e) {
            stopWatch.stop();
            // Log method error with exception details
            logMethodError(fullMethodName, e, stopWatch.getTotalTimeMillis());
            throw e;
        }
    }

    private void logMethodEntry(String methodName, Object[] args) {
        String parameters = Arrays.stream(args)
                .map(arg -> {
                    if (arg == null) {
                        return "null";
                    }
                    // Mask sensitive data
                    return maskSensitiveData(arg.toString(), methodName);
                })
                .collect(Collectors.joining(", "));

        log.info("🚀 ENTRY: {} - Parameters: [{}]", methodName, parameters);
    }

    private void logMethodExit(String methodName, Object result, long executionTime) {
        if (result != null) {
            String resultString = maskSensitiveData(result.toString(), methodName);
            log.info("✅ EXIT: {} - Result: [{}] - Execution Time: {}ms",
                    methodName, resultString, executionTime);
        } else {
            log.info("✅ EXIT: {} - Execution Time: {}ms", methodName, executionTime);
        }
    }

    private void logMethodError(String methodName, Exception e, long executionTime) {
        log.error("❌ ERROR: {} - Exception: {} - Execution Time: {}ms",
                methodName, e.getMessage(), executionTime);
    }

    private String maskSensitiveData(String data, String methodName) {
        // Mask passwords, tokens, and other sensitive information
        if (data.contains("password") || data.contains("Password")) {
            return data.replaceAll("(\"password\"\\s*:\\s*\")[^\"]*(\")", "$1*****$2");
        }
        if (data.contains("token") || data.contains("Token")) {
            return data.replaceAll("(\"token\"\\s*:\\s*\")[^\"]*(\")", "$1*****$2");
        }
        if (methodName.contains("login") || methodName.contains("register")) {
            // Additional masking for auth-related methods
            return data.replaceAll("(\"password\"\\s*:\\s*\")[^\"]*(\")", "$1*****$2");
        }
        return data;
    }
}
