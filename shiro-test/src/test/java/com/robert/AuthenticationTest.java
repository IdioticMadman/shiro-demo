package com.robert;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationTest {

    private SimpleAccountRealm realm = new SimpleAccountRealm();

    private DruidDataSource druidDataSource = new DruidDataSource();
    @Before
    public void setUp() {
        realm.addAccount("robert", "123456", "admin");
        druidDataSource.setUrl("jdbc:mysql://localhost:3306/shiro_demo");
        druidDataSource.setUsername("root");
        druidDataSource.setPassword("123456");
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
        //是否认证
        System.out.println("isAuthenticated: " + subject.isAuthenticated());
        subject.checkRoles("admin");
        //退出
        subject.logout();
        System.out.println("isAuthenticated: " + subject.isAuthenticated());
    }

    @Test
    public void testIniAuthentication(){
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //配置IniRealm
        IniRealm realm = new IniRealm("classpath:user.ini");
        securityManager.setRealm(realm);

        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("robert","123456");
        subject.login(token);

        subject.checkRoles("admin");

        subject.checkPermission("user:update");
    }

    @Test
    public void testJDBCAuthentication(){
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(druidDataSource);
        securityManager.setRealm(jdbcRealm);

        jdbcRealm.setAuthenticationQuery("select userpassword from test_users where username=?");

        jdbcRealm.setUserRolesQuery("select rolename from test_users_roles where username=?");

        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("robert","123456");
        subject.login(token);

        subject.checkRoles("admin");

//        subject.checkPermission("user:update");
    }
}
