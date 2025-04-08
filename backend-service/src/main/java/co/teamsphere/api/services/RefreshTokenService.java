package co.teamsphere.api.services;

import java.util.Optional;

import org.springframework.stereotype.Service;

import co.teamsphere.api.exception.RefreshTokenException;
import co.teamsphere.api.exception.UserException;
import co.teamsphere.api.models.RefreshToken;

@Service
public interface RefreshTokenService {
    RefreshToken createRefreshToken(String email) throws UserException;

    Optional<RefreshToken> findRefreshToken(String refreshToken);

    RefreshToken verifyExpiration(RefreshToken token) throws RefreshTokenException;
    
    void deleteRefreshTokenByUserId(String userId);

    RefreshToken findByUserId(String userId);

    String replaceRefreshToken(String userId);
}
