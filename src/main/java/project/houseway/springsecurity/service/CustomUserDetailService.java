package project.houseway.springsecurity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import project.houseway.springsecurity.domain.User;
import project.houseway.springsecurity.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    //JPA를 사용해서 사용자 정보를 데이터베이스에서 조회하고 그 결과를 UserDetails 객체에 저장하여 반환
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //JPA와 MariaDB를 이용해서 사용자 정보 확인
        User user = userRepository.findByUserid(username).orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

        //인증에 성공하면 userdetails 객체 생성하고 반환
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUserid())
                .password(user.getPasswd())
                .roles("USER")
                .build();
    }
}
