package com.bfmarcelino.todolist.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import at.favre.lib.crypto.bcrypt.BCrypt;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private IUserRepository userRepository;
    
    @PostMapping("/")
    public ResponseEntity create(@RequestBody UserModel userModel){
        //verifica se userName ja está em uso
        var user = this.userRepository.findByUsername(userModel.getUsername());
        if(user != null){
            //Retorno do ResponseEntity com status HTTP de Bad_Request e um body com texto de usuário existente no banco
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Esse UserName já está cadastrado");
        }

        var passwordHashed = BCrypt.withDefaults().hashToString(12, userModel.getPassword().toCharArray());
        userModel.setPassword(passwordHashed);

        //Envia para o Repository salvar o userModel
        UserModel userCreated = this.userRepository.save(userModel);
        //Retorno do ResponseEntity com status HTTP de Created com um body do proprio userModel do usuario criado
        return ResponseEntity.status(HttpStatus.CREATED).body(userCreated);
    }
}
