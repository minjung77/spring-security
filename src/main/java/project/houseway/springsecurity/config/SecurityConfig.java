package project.houseway.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import project.houseway.springsecurity.jwt.JwtAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

//    private final UserDetailsService userDetailService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // SecurityFilterChain : 스프링 시큐리티에서 적용된 보안규칙들을 필터로 구현해 둔 것
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()//CSRF 필터를 끔
//                    .userDetailsService(userDetailService)
                    .authorizeRequests()//url 기반 인가 설정
                    .antMatchers("/user/**").hasRole("USER")// user 권한 사용자만 접근
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/logout").authenticated()// 인증 받은 사용자감 접근 가능
                    .antMatchers("/**", "/member/**").permitAll()// 인증/인가 여부와 상관없이 접근 가능
                    .and()
//                .formLogin()
//                    .loginPage("/member/login") //커스텀 로그인 페이지 설정
//                    .usernameParameter("userid") //아이디 매개변수 지정
//                    .passwordParameter("passwd") //비밀번호 매개변수 지정
//                    .defaultSuccessUrl("/")//로그인 성공 시 리다이텍트 url
//                    .failureUrl("/login?error=true")//로그인 실패시 리다이렉트 url
//                    .permitAll()
//                    .and()
//                .logout()// 로그아웃 설정
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                    .logoutSuccessUrl("/")// 로그아웃 성공 후 리다이렉트될 url
//                    .invalidateHttpSession(true)// 세션 무효화
//                    .deleteCookies("JSESSIONED")//JSESSIONID 쿠키 삭제
//                    .permitAll();

                //jwt 인증으로 변경
                .sessionManagement()//jwt인증을 위해 stateless 설정
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //jwt 필터 설정
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {// 비밀번호 암호화에 사용할 인코더
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
