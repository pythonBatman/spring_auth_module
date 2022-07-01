package it.spring.auth_module.auth.roles;

import it.spring.auth_module.models.AppUser;
import it.spring.auth_module.utils.AppSession;
import it.spring.auth_module.utils.Responses;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;
import java.util.Arrays;

@Aspect
@Configuration
public class AuthAspect {
    @Around("@annotation(it.spring.auth_module.auth.roles.AuthRoles)")
    public Object check(ProceedingJoinPoint call) throws Throwable {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpSession session = requestAttributes != null ? requestAttributes.getRequest().getSession() : null;
        if (session == null) {
            Responses.internalServerError();
        }
        AppUser appUser = AppSession.getAuthUser(session);
        if (appUser == null) {
            Responses.unauthorized();
        }
        MethodSignature methodSignature = (MethodSignature) call.getSignature();
        AuthRoles.Roles[] authRoles = methodSignature.getMethod().getAnnotation(AuthRoles.class).value();
        if (authRoles.length > 0 && Arrays.stream(authRoles).noneMatch((e) -> e.equals(appUser.getRole()))) {
            Responses.forbiddenResource();
        }
        return call.proceed();
    }
}
