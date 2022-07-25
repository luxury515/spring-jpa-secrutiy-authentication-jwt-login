# spring-jpa-secrutiy-authentication-jwt-login
### yml setting

### 기초데이터
```
INSERT INTO roles(name) VALUES('ROLE_USER');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');
```
### postman api
- For join
```
http://localhost:{port}}/api/auth/signup
json:
{
    "username":"cai1",
    "email":"cai1@gmail.com",
    "password":"123456",
    "role":["ROLE_USER","ROLE_ADMIN"]
}
```
- For login
```
http://localhost:{port}}/api/auth/login
json:
{
    "username":"cai1",
    "password":"123456"
}
```