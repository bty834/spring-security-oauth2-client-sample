Simple usage of Spring Security OAuth2 Rest Client & Authorization Server

- Authorization Server: support both OAuth2.0 and OAuth2.1 ,including Resource Server
- Rest Client: Rest Rest Rest~

一些参考

- 关于**OAuth2.0**规范介绍请参考 [OAuth 2.0 Simplified](https://www.oauth.com/)
- 关于**OAuth2.1**草案介绍请参考 [OAuth 2.1](https://oauth.net/2.1/)

- 关于Spring Security中OAuth2.0在前后端分离架构下的授权流程可以参考: [前后端分离：Spring Security OAuth2.0第三方授权](https://blog.csdn.net/weixin_41866717/article/details/127092895)
- 关于源码解读，可参考[我的博客](https://www.btyhub.site/post)中Spring Security专栏

注意：运行client时，请在application.yml中指定profile，样例如application-test.yml中所示