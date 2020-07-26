package br.com.alura.forum.config.security;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenService {

    @Value("${forum.jwt.expiration}")
    private String expiration;      //Valor "injetado" lá do arquivo application.properties

    @Value("${forum.jwt.secret}")
    private String secret;      //Valor "injetado" lá do arquivo application.properties

    public String gerarToken(Authentication authentication) {

        Usuario logado = (Usuario) authentication.getPrincipal();
        Date hoje = new Date();
        Date dataExpiracao = new Date(hoje.getTime() + Long.parseLong(expiration));

        return Jwts.builder()
                .setIssuer("API do Fórum da Aulra")         //Quem fez a geração do token.
                .setSubject(logado.getId().toString())      //Quem é o usuário autenticado que esse token pertence.
                .setIssuedAt(hoje)                          //Data de criação do token.
                .setExpiration(dataExpiracao)               //Data de expiração do token, no caso, em milisegundos.
                .signWith(SignatureAlgorithm.HS256, secret) //Algoritmo p/ encriptografar, e sua respectiva chave.
                .compact();
    }

    public boolean isTokenValido(String token) {
        try{
            Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
            return true;
        }catch (Exception e){
            return false;
        }
    }

    public Long getIdUsuario(String token) {
        Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
        return Long.parseLong(claims.getSubject());
    }
}
