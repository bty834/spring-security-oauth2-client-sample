# 工程简介
Spring Security 前后端分离Oauth2.0

![](./docs/images/Oauth2前后端分离.png)
![](./docs/images/details.png)



当要使用oauth2.0第三方登录时，uri默认的pattern为 `/oauth2/authorization/{registration_id}`，例如：
我这里用gitee登录，那么后台接口为 `http://localhost:8080/oauth2/authorization/gitee` ，
这样spring security的filter `OAuth2AuthorizationRequestRedirectFilter` 才能识别这是一个oauth2.0的请求。
然后，在第三方设置回调接口时（也就是返回code的回调地址，yml里面的redirect-uri和gitee后台配置的回调地址），
默认的pattern为`/login/oauth2/code/{registration_id}`。当然以上都是默认配置，可以自定义。
另外，普通的用户名密码登录的POST请求要设置编码格式为：`x-www-form-urlencoded`，
如果你设置为`application/json`是无法解析的，因为默认的类`UsernamePasswordFilter`是通过`request.getParameter()`方式获取的。
`getParamter()`这种在POST方式下只支持`x-www-form-urlencoded`

另外，自定义功能需要看看[spring security官网](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html)和[Protocol Endpoints](https://www.rfc-editor.org/rfc/rfc6749#section-3)
几个重要的endpoint顺序：
Authorization Endpoint 获取授权阶段，授权码模式下就是获取授权码
Redirection Endpoint 重定向阶段，拿到授权码开始重定向
Token Endpoint  拿着授权码获取access-token
UserInfo Endpoint 拿着access-token获取资源
![img.png](docs/images/img.png)
注意：OAuth2.0协议中的client指的是用户代理，如服务器。resource owner指的是用户，就是人。别搞混了

(swagger这个我去掉了，下面是坑)
swagger2.0注释接口信息
swagger2 3.0.0版本和spring security有冲突
3.0.0版本无法访问swagger的页面，一直403，即使在WebSecurity中ignore相关页面也不行。
2.9.2版本正常
另外，
swagger2
3.0.0以下版本访问 /swagger-ui.html
3.0.0版本访问 /swagger-ui/index.html
