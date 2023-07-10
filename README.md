# gencheck-key

Implementação da cifração e decifração AES, chave 128 bits como também a geração de chaves e cifra RSA com teste de primalidade Miller-Rabin.

### Dependencias

* rustc 1.70.0 (90c541806 2023-05-31)
* cargo 1.70.0 (ec8a8a0ca 2023-04-25)

### Instalando

* Clone esse repo
* Dentro da pasta gencheck-key execute o comando `cargo build`

### Executando o projetos

A pasta results deve conter os dados de saida e entrada do programa.

Na raiz do projeto execute os seguintes comandos:

Para gerar chaves AES:

```
cargo run -- generate_aes_key
```

Para codificar mensagem AES:

```
cargo run -- aes_encode
```

Para decodificar mensagem AES:

```
cargo run -- aes_decode
```

Para gerar chaves RSA:

```
cargo run -- generate_rsa_key
```

Para codificar mensagem RSA:

```
cargo run -- rsa_oaep_encode
```

Para decodificar mensagem RSA:

```
cargo run -- rsa_oaep_aes_decode
```

## Autores

Thiago Tokarski 190096063

## Referencias

Inspiration, code snippets, etc.
* [Aritmética 1024 bits](https://glitchcomet.com/articles/1024-bit-primes/)
* [AES](https://www.youtube.com/watch?v=O4xNJsjtN6E&t=313s)
* [RSA](https://www.youtube.com/watch?v=4zahvcJ9glg)