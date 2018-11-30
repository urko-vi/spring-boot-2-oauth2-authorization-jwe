Spring Boot 2 Oauth Sever

authorization_code --> sirve para la comunicación entre aplicaciones y se usa mucho. Por ejemplo cuando dejamos acceder a nuestra cuenta de Gmail a traves de un token de acceso.
refresh_token --> se pide un refresco del token pq ha caducado
password  --> se mandan las credenciales del usuario, las del propietario del recurso (Ej. contraseñas de Twitter). no es el mas recomendado por temas evidentes.
client_credentials -->se mandan las credenciales del usuario, las del cliente (identificador y clave que no tienen que ver con las del usuario).