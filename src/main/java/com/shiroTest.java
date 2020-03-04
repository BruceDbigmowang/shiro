package com;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class shiroTest {
    @Test
    public void loginTest(){
        //认证操作
        //加载资源文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:config/shiro.ini");
        //创建资源安全管理器
        SecurityManager securityManager = factory.getInstance();
        //把安全管理器设置到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //通过安全工具类创建Subject主体对象
        Subject subject = SecurityUtils.getSubject();
        //创建用户认证令牌
        UsernamePasswordToken token = new UsernamePasswordToken("admin" , "admin");
        try{
            //通过subject主体的login方法来进行认证
            subject.login(token);
            System.out.println("验证通过");
        }catch (Exception e){
            System.out.println("验证失败");
            e.printStackTrace();
        }
        //判断认证结果
        boolean authenticated = subject.isAuthenticated();
        System.out.println(authenticated);

        //退出系统
        subject.logout();


    }
    @Test
    public void TestRealm(){
        //认证操作
        //加载资源文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:config/shiro_realm.ini");
        //创建资源安全管理器
        SecurityManager securityManager = factory.getInstance();
        //把安全管理器设置到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //通过安全工具类创建Subject主体对象
        Subject subject = SecurityUtils.getSubject();
        //创建用户认证令牌
        UsernamePasswordToken token = new UsernamePasswordToken("admin" , "admin");
        try{
            //通过subject主体的login方法来进行认证
            subject.login(token);
            System.out.println("验证通过");
        }catch (Exception e){
            System.out.println("验证失败");
            e.printStackTrace();
        }
        //判断认证结果
        boolean authenticated = subject.isAuthenticated();
        System.out.println(authenticated);

        //退出系统
        subject.logout();

    }
/*21232f297a57a5a743894a0e4a801fc3*/
    @Test
    public void md5Test(){
        //加密算法测试
        String password = "admin";
        String salt = "wangm0908";
        int hashIterations = 6;

        //Md5Hash md5Hash = new Md5Hash(password , salt , hashIterations);
        SimpleHash simpleHash = new SimpleHash("md5" , password , salt , hashIterations);
        System.out.println(simpleHash);
    }

    @Test
    public void Md5RealmTest(){
        //认证操作
        //加载资源文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:config/shiro_md5.ini");
        //创建资源安全管理器
        SecurityManager securityManager = factory.getInstance();
        //把安全管理器设置到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //通过安全工具类创建Subject主体对象
        Subject subject = SecurityUtils.getSubject();
        //创建用户认证令牌
        UsernamePasswordToken token = new UsernamePasswordToken("admin" , "admin");
        try{
            //通过subject主体的login方法来进行认证
            subject.login(token);
            System.out.println("验证通过");
        }catch (Exception e){
            System.out.println("验证失败");
            e.printStackTrace();
        }
        //判断认证结果
        boolean authenticated = subject.isAuthenticated();
        System.out.println(authenticated);

        //退出系统
        subject.logout();
    }

    @Test
    public void testPermitted(){
        //认证操作
        //加载资源文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:config/shiro_permitted.ini");
        //创建资源安全管理器
        SecurityManager securityManager = factory.getInstance();
        //把安全管理器设置到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //通过安全工具类创建Subject主体对象
        Subject subject = SecurityUtils.getSubject();
        //创建用户认证令牌
        UsernamePasswordToken token = new UsernamePasswordToken("admin" , "admin");
        try{
            //通过subject主体的login方法来进行认证
            subject.login(token);
            System.out.println("验证通过");
        }catch (Exception e){
            System.out.println("验证失败");
            e.printStackTrace();
        }
        //判断认证结果
        boolean authenticated = subject.isAuthenticated();
        System.out.println(authenticated);

        boolean hasRole = subject.hasRole("role1");
        System.out.println("admin拥有role1权限"+hasRole);

        boolean hasPermitted = subject.isPermitted("user:update");
        System.out.println("admin拥有创建的权限"+hasPermitted);

        boolean flag = subject.hasAllRoles(Arrays.asList("role1" , "role2" , "role3"));
        System.out.println("admin拥有全部权限"+flag);

        boolean permition = subject.isPermittedAll("user:create" , "user:delete");
        System.out.println("admin是否拥有多个权限"+permition);
        //退出系统
        subject.logout();
    }

    @Test
    public void testPermittedRealm(){
        //认证操作
        //加载资源文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:config/shiro_permitted_realm.ini");
        //创建资源安全管理器
        SecurityManager securityManager = factory.getInstance();
        //把安全管理器设置到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        //通过安全工具类创建Subject主体对象
        Subject subject = SecurityUtils.getSubject();
        //创建用户认证令牌
        UsernamePasswordToken token = new UsernamePasswordToken("admin" , "admin");
        try{
            //通过subject主体的login方法来进行认证
            subject.login(token);
            System.out.println("验证通过");
        }catch (Exception e){
            System.out.println("验证失败");
            e.printStackTrace();
        }
        //判断认证结果
        boolean authenticated = subject.isAuthenticated();
        System.out.println(authenticated);

        boolean hasRole = subject.hasRole("role1");
        System.out.println("admin拥有role1权限"+hasRole);

        boolean hasPermitted = subject.isPermitted("user:update");
        System.out.println("admin拥有创建的权限"+hasPermitted);
        boolean flag = subject.hasAllRoles(Arrays.asList("role1" , "role2" , "role3"));
        System.out.println("admin拥有全部权限"+flag);

        boolean permition = subject.isPermittedAll("user:create" , "user:delete");
        System.out.println("admin是否拥有多个权限"+permition);
        //退出系统
        subject.logout();
    }
}
