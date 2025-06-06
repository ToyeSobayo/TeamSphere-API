package co.teamsphere.api.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SendMessageRequest {
    private UUID chatId;
    private UUID userId;
    private String content;
}
