package io.security.basicsecurity.service.impl;

import io.security.basicsecurity.domain.entity.RoleHierarchy;
import io.security.basicsecurity.repository.RoleHierarchyRepository;
import io.security.basicsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarchy() {

        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
        StringBuffer concatedRoles = new StringBuffer();
        // 권한 계츨 포맷팅해서 리턴
        while (itr.hasNext()) {
            RoleHierarchy model = itr.next();
            if (model.getParentName() != null) {
                concatedRoles.append(model.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(model.getChildName());
                concatedRoles.append("\n");
            }
        }
        return concatedRoles.toString();

    }
}
