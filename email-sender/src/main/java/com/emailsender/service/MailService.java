package com.emailsender.service;

import com.emailsender.config.RabbitConfig;
import com.resend.Resend;
import com.resend.core.exception.ResendException;
import com.resend.services.emails.model.CreateEmailOptions;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service @RequiredArgsConstructor
public class MailService {

    private final TemplateEngine templateEngine;
    @Value("${resend.token}")
    private String token;

    @RabbitListener(queues = RabbitConfig.QUEUE_EMAIL)
    public void emailRequest(UsuarioDTO user) {
        String urlVerication = "http://localhost:8080/auth/verify/"+ user.token();
        Resend resend = new Resend(token);
        Context context = new Context();
        context.setVariable("nombre",user.username());
        context.setVariable("enlaceVerificacion",urlVerication);
        String contenidoHtml = templateEngine.process("template-emailVerificacion",context);
        try {
            CreateEmailOptions params = CreateEmailOptions.builder()
                    .from("onboarding@resend.dev")
                    .to(user.email())
                    .subject("Confirmación de cuenta")
                    .html(contenidoHtml)
                    .build();
            resend.emails().send(params);
        } catch (ResendException e) {
            throw new RuntimeException("Error al enviar el correo");
        }
    }
}
