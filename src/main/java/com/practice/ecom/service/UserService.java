package com.practice.ecom.service;

import com.practice.ecom.dao.RoleDao;
import com.practice.ecom.dao.UserDao;
import com.practice.ecom.entity.Role;
import com.practice.ecom.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {

    @Autowired
    private UserDao userDao;
    @Autowired
    private RoleDao roleDao;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void initRoleAndUser() {

        Role adminRole = new Role();
        adminRole.setRoleName("Admin");
        adminRole.setRoleDescription("Application Administrator");
        roleDao.save(adminRole);

        Role userRole = new Role();
        userRole.setRoleName("User");
        userRole.setRoleDescription("Default Role for new Users");
        roleDao.save(userRole);

        User adminUser = new User();
        adminUser.setUserName("admin");
        adminUser.setUserPassword(getEncodedPassword("admin@pass"));
        adminUser.setUserFirstName("admin");
        adminUser.setUserLastName("admin");
        Set<Role> adminRoles = new HashSet<>();
        adminRoles.add(adminRole);
        adminUser.setUserRoles(adminRoles);
        userDao.save(adminUser);
    }

    public User registerNewUser(User user){

        Role role = roleDao.findById("User").get();

        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setUserRoles(roles);
        user.setUserPassword(getEncodedPassword(user.getUserPassword()));

        return userDao.save(user);
    }

    public String getEncodedPassword(String password) {
        return passwordEncoder.encode(password);
    }
}
