package project.houseway.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // SecurityFilterChain : 스프링 시큐리티에서 적용된 보안규칙들을 필터로 구현해 둔 것
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()//CSRF 필터를 끔
                    .authorizeRequests()//url 기반 인가 설정
                    .antMatchers("/user/**").hasRole("USER")// user 권한 사용자만 접근
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/logout").authenticated()// 인증 받은 사용자감 접근 가능
                    .antMatchers("/**").permitAll()// 인증/인가 여부와 상관없이 접근 가능
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessHandler((req, res, auth) -> {
                        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);//로그아웃을 위해 401응답
                    })
                    .invalidateHttpSession(true)//세션 무효화
                    .deleteCookies("JSESSIONED")//JSESSIONID 쿠키 삭제
                    .permitAll()
                    .and()
                .httpBasic();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {// 비밀번호 암호화에 사용할 인코더
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
//                .roles("ADMIN", "USER")
                .roles("ADMIN")// admin 권한 가짐
                .build();
        
        return new InMemoryUserDetailsManager(user, admin);//계정 2개를 메모리에 저장
    }
}
