package com.ulayera.security.service;

import com.ulayera.security.model.User;
import com.ulayera.security.repository.UserRepository;
import com.ulayera.security.security.JwtService;
import com.ulayera.security.web.model.AuthRequest;
import com.ulayera.security.web.model.AuthResponse;
import com.ulayera.security.web.model.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.ulayera.security.model.Role.USER;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse register(RegisterRequest request) {
        final User user = User.builder()
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(USER)
            .build();
        userService.save(user);
        return getAuthResponse(user);
    }

    public AuthResponse authenticate(AuthRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            )
        );
        User user = this.userService.findByEmail(request.getEmail())
            .orElseThrow();
        return getAuthResponse(user);
    }

    private AuthResponse getAuthResponse(User user) {
        return AuthResponse.builder().token(jwtService.generateToken(user)).build();
    }
}
