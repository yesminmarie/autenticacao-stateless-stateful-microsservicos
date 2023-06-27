package br.com.microservice.statefulauthapi.core.service;

import br.com.microservice.statefulauthapi.core.dto.AuthRequest;
import br.com.microservice.statefulauthapi.core.dto.AuthUserResponse;
import br.com.microservice.statefulauthapi.core.dto.TokenDTO;
import br.com.microservice.statefulauthapi.core.model.User;
import br.com.microservice.statefulauthapi.core.repository.UserRepository;
import br.com.microservice.statefulauthapi.infra.exception.AuthenticationException;
import br.com.microservice.statefulauthapi.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public TokenDTO login(AuthRequest request){
        var user = findByUsername(request.username());
        var accessToken = tokenService.createToken(user.getUsername());
        validatePassword(request.password(), user.getPassword());
        return new TokenDTO(accessToken);
    }
    private void validatePassword(String rawPassword, String encodedPassword) {
        if(isEmpty(rawPassword)){
            throw new ValidationException("The password must be informed!");
        }
        if(!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("The password is incorrect!");
        }
    }

    public TokenDTO validateToken(String accessToken){
        validateExistingToken(accessToken);
        var valid = tokenService.validateAccessToken(accessToken);
        if(valid) {
            return new TokenDTO(accessToken);
        }
        throw new AuthenticationException("Invalid token!");
    }

    public AuthUserResponse getAuthenticatedUser(String accessToken){
        var tokenData = tokenService.getTokenData(accessToken);
        var user = findByUsername(tokenData.username());
        return new AuthUserResponse(user.getId(), user.getUsername());
    }

    public void logout(String accessToken) {
        tokenService.deleteRedisToken(accessToken);
    }

    private User findByUsername(String username){
        return repository
                .findByUsername(username)
                .orElseThrow(() -> new ValidationException("User not found!"));
    }
    private void validateExistingToken(String acessToken){
        if(isEmpty(acessToken)){
            throw new ValidationException("The access token must be informed!");
        }
    }
}
