package com.bfmarcelino.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bfmarcelino.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            var servletPath = request.getServletPath();
            if(servletPath.startsWith("/tasks/")){

                //pegar a autenticação(usuario e senha)
                var authorization = request.getHeader("Authorization");
                //System.out.println("Authorization");
                //System.out.println(authorization);
                
                
                //pega o dado criptografado
                var authEncoded = authorization.substring("Basic".length()).trim();
                //System.out.println("authEncoded");
                //System.out.println(authEncoded);

                //Returns a Decoder that decodes using the Basic type base64 encoding scheme
                //A newly-allocated byte array containing the decoded bytes.
                byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
                //System.out.println("authDecoded");
                //System.out.println(authDecoded);
                
                //passa para String o array de bytes do base64
                var authString = new String(authDecoded);
                
                //separa a credencial em usuario e senha com o split :
                String[] credentials = authString.split(":");
                String usuario = credentials[0];
                String password = credentials[1];
                
                //System.out.println(usuario);
                //System.out.println(password);
                
                
                //validar usuario
                var user = this.userRepository.findByUsername(usuario);
                if(user == null){
                    response.sendError(401);
                }else{
                    //validar senha
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(),user.getPassword());
                    if(passwordVerify.verified){
                        //segue próxima etapa
                        request.setAttribute("idUser", user.getId());
                        filterChain.doFilter(request,response);
                    }
                    else{
                        response.sendError(401);
                    }
                }
            }else{
                //segue próxima etapa
            filterChain.doFilter(request,response);
            }  
    }
}
