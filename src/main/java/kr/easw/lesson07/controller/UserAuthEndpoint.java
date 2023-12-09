package kr.easw.lesson07.controller;

import kr.easw.lesson07.model.dto.ExceptionalResultDto;
import kr.easw.lesson07.model.dto.UserAuthenticationDto;
import kr.easw.lesson07.model.dto.UserDataEntity;
import kr.easw.lesson07.service.UserDataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class UserAuthEndpoint {
    private final UserDataService userDataService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    // JWT 인증을 위해 사용되는 엔드포인트입니다.
    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody UserDataEntity entity) {
        try {
            // 로그인을 시도합니다.
            return ResponseEntity.ok(userDataService.createTokenWith(entity));
        } catch (Exception ex) {
            // 만약 로그인에 실패했다면, 400 Bad Request를 반환합니다.
            return ResponseEntity.badRequest().body(new ExceptionalResultDto(ex.getMessage()));
        }
    }


    @PostMapping("/register")
    public ResponseEntity<Object> register(HttpServletRequest request) {
        try {
            String userId = request.getParameter("username");
            String rawPassword = request.getParameter("password");

            // 사용자의 존재 여부를 확인합니다.
            if (userDataService.isUserExists(userId)) {
                return ResponseEntity.badRequest().body("User already exists");
            }

            // 비밀번호를 암호화합니다.
            String encryptedPassword = bCryptPasswordEncoder.encode(rawPassword);

            // 새로운 사용자 객체를 생성하고 비밀번호를 설정합니다.
            UserDataEntity newUser = new UserDataEntity(0L, userId, encryptedPassword, false);
            userDataService.createUser(newUser);

            return ResponseEntity.ok("User successfully registered");
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body("Registration failed: " + ex.getMessage());
        }
    }
}
