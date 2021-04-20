package io.security.basicsecurity.service.impl;

import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.repository.UserRepository;
import io.security.basicsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service("userService")
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }

}
