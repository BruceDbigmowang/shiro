package com.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.List;

public class PermittedRealm extends AuthorizingRealm {
    /**
     * 授权方法
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取用户名信息
        String username = principalCollection.getPrimaryPrincipal().toString();
        System.out.println("username"+username);
        //根据用户名从数据库中获取角色信息
        String[] roles = {"role1" ,"role2" , "role3"};
        //定义权限列表
        List<String> permittions = new ArrayList<String>();
        //遍历角色，获取角色拥有的权限
        for(String role:roles ){
            System.out.println(role);
            permittions.add("user:creste");
            permittions.add("user:delete");
            permittions.add("user:update");
            permittions.add("user:*");
        }
        SimpleAuthorizationInfo simpleAuthenticationInfo = new SimpleAuthorizationInfo();
        simpleAuthenticationInfo.addStringPermissions(permittions);
        return simpleAuthenticationInfo;
    }

    /**
     * 认证方法
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username = authenticationToken.getPrincipal().toString();
        //根据用户名获取密码
        String password = "admin";//此处应为从数据库中查询密码
        if(password == null || "".equals(password)){
            return null;
        }
        //把用户名和密码封装到AuthenticationInfo的实现类中
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username , password , "PermittedRealm");
        return simpleAuthenticationInfo;
    }
}
