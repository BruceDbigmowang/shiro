package com.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.Test;

public class MyRealm extends AuthorizingRealm {
    //授权方法
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }
    //认证方法
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //通过token令牌来获取账号信息
        String username = (String)authenticationToken.getPrincipal();
        //根据用户名查询数据库中的密码
        String password = "admin"; //此处省略数据库查询操作
        if(password == null || "".equals(password)){
            return null;
        }
        //把用户名 密码 域封装到SimpleAuthenticationInfo对象中
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username , password , "myRealm");
        return simpleAuthenticationInfo;
    }
}
