package com.example.security.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.security.entity.Permission.*;

@RequiredArgsConstructor
public enum Role {
    TEACHER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_CREATE,
                    MANAGER_READ,
                    MANAGER_UPDATE,
                    MANAGER_DELETE,
                    MANAGER_CREATE

            )
    ),
    USER(Collections.emptySet()),
    MANAGER(
            Set.of(
            MANAGER_READ,
            MANAGER_UPDATE,
            MANAGER_DELETE,
            MANAGER_CREATE

    ));

    @Getter
    private final Set<Permission> permissionSet;

    public List<SimpleGrantedAuthority> getAuthorities(){
     var authorities = getPermissionSet()
             .stream()
             .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
             .collect(Collectors.toList());
     authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
     return authorities;
    }
}
