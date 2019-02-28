package com.robert;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationTest {

    private SimpleAccountRealm realm = new SimpleAccountRealm();

    @Before
    public void setUp() {
        realm.addAccount("robert", "123456");
    }

    @Test
    public void testAuthentication() {
        //1. 构建SecurityManager环境
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(realm);

        //2. 主体提交认证
        SecurityUtils.setSecurityManager(securityManager);


        UsernamePasswordToken token = new UsernamePasswordToken("robert", "123456");
        Subject subject = SecurityUtils.getSubject();
        subject.login(token);

        System.out.println("isAuthenticated: " + subject.isAuthenticated());
    }
}
