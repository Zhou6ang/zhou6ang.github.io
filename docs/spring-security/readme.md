# Spring Security 5.x + OAuth2.0 + OIDC1.0


# 前言

之前学习springboot集成spring security的OAauth2.1和OIDC1.0遇到的问题及成功情况，这里做个笔记下次好查看。

---



# 一、准备工作

## 1.Spring Security相关依赖包
```xml
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.7.0</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
...
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			  <artifactId>spring-security-oauth2-authorization-server</artifactId>
			  <version>0.3.0</version>
		</dependency>
		 <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
        </dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
		</dependency>

		<dependency>
			<groupId>com.nimbusds</groupId>
			<artifactId>oauth2-oidc-sdk</artifactId>
		</dependency>
```

## 2.先看下Authorization Code Grant经典图
![在这里插入图片描述](./Authorization_Code_Grant.png)

## 2.还是画个结构草图
![workflow](./auth_code_work_flow.png)


# 二、创建对应微服务
## 1.创建springboot-oauth2-server服务
结构如下所示:
![在这里插入图片描述](./code_structure.png)


>核心类MyAuthorizationServerConfig如下：

```java
package com.example.demo.config;
...
@EnableWebSecurity
public class MyAuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//        http.exceptionHandling((exceptions) -> exceptions
//                        .authenticationEntryPoint(
//                                new LoginUrlAuthenticationEntryPoint("/login"))
//                );
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        //customized authorizationEndpoint,redirectionEndpoint,tokenEndpoint,userInfoEndpoint
//        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(userinfo ->
//        userinfo.oidcUserService(oauth2UserService())
//        )
//        .oauth2.tokenEndpoint(...)
//        );

        //if defined http.exceptionHandling then no need to define http.formLogin(Customizer.withDefaults())
        return http.formLogin(Customizer.withDefaults()).build();
    }


    //for authorization_code purpose
    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
      
      //authorization_code
        RegisteredClient loginClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("login-client")
                .clientSecret("{noop}openid-connect")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/login-client")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
//                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        //client credential
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                /**
                 * curl -X POST \
                  http://127.0.0.1:8080/oauth2/token \
                  -H 'cache-control: no-cache' \
                  -H 'content-type: application/x-www-form-urlencoded' \
                  -H 'postman-token: b8d3bbd1-b796-b2a2-eecf-c37277868eb6' \
                  -d 'grant_type=client_credentials&scope=message%3Aread&client_id=messaging-client&client_secret=secret'
                 */
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("message:read")
                .scope("message:write")
                .build();
      
        return new InMemoryRegisteredClientRepository(loginClient, registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }


    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:9001").build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123")
                .roles("USER")
                .build();
//      MyUser u = new MyUser(1, "user", "12345");
//      PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//      UserDetails userDetails = new User(u.getUsername(), passwordEncoder.encode(u.getPassword()), u.getAuthorities());
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }    
}

```
application.yml啥也没配置，可以配置clientid和secret等但是正确的做法是把它们放入到数据库(JdbcRegisteredClientRepository)，这里将就用内存(InMemoryRegisteredClientRepository)了

```xml
logging.level.root: debug
server:
  port: 9001
  
```
`注意点：`
1. 采用[官方配置](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html)缺了下面

> http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

导致resource server获取/userinfo报错

> ```[invalid_user_info_response] An error occurred while attempting to retrieve the UserInfo Resource: 401 : [no body] ```

![在这里插入图片描述](./error_case_1.png)
看了下原因没有加http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);导致了BearerTokenAuthenticationFilter的缺失，所以当resource server发起最后一步的userinfo请求的时候就会出现HTTP/1.1 401 Unauthorized, 如下：

> curl --location --request GET 'http://localhost:9001/userinfo' \
--header 'Authorization: Bearer eyJraWQiOiIyNDZiZDJiMi05YzZkLTQwYTQtOTU3Yi00YTc1Yjc1MDMwMzgiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibG9naW4tY2xpZW50IiwibmJmIjoxNjUzNzk4NDI0LCJzY29wZSI6WyJvcGVuaWQiLCJwcm9maWxlIl0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo5MDAxIiwiZXhwIjoxNjUzNzk4NzI0LCJpYXQiOjE2NTM3OTg0MjR9.XI42mxbD3IEzHs4NvLoL5jU3amf_wQazm3AIKbdTB-6x4WD0_dWP9ZrYFUMyu3WaqeQdAwaqrl1D680T-4evjCkjaMSUAfFewg1C4j3wzZ6Fhy3R8gtBn_7qnFwAD8Uz1T9ElZhDVbXTgsK9R55nc93bAl8dDbD0ZTo0BYnp0nUXgRyErDbzylhVISXHgqZz4SYyEIYyOe3ipb7AR2ffGWqutZheqOL0QB4mjVcZNVMqHbDEPM-3d6sLnBFoEFn-RjLSMcvv1ZnBFNVEHdwDs2GI4OV8oonygRKCC6XsmFFmiBrtw_veOQzJuhXWGQmjvzjrfe_I0LN5xmBGjCMmlw'
---------------------------------------respnse-------------------------
 < HTTP/1.1 401
< Set-Cookie: JSESSIONID=9E6B72EA9F40647AA576242318C8EB31; Path=/; HttpOnly
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Length: 0

2. 下面这个配置也挺重要的，如果配置了exceptionHandling则可以不用formLogin(Customizer.withDefaults())，如果没有配置exceptionHandling则一定加上formLogin(Customizer.withDefaults())

```xml
   @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//        http.exceptionHandling((exceptions) -> exceptions
//                        .authenticationEntryPoint(
//                                new LoginUrlAuthenticationEntryPoint("/login"))
//                );
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        //if defined http.exceptionHandling then no need to define http.formLogin(Customizer.withDefaults())
        return http.formLogin(Customizer.withDefaults()).build();
    }
```
否则/oauth2/authorize会出现401 Unauthorized情况：

> http://localhost:9001/oauth2/authorize?response_type=code&client_id=login-client&scope=openid%20profile&state=CczwBMaNiABNPyEeB-r_t1FIL5Rz0d80gaJKJBRC6ho%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/login-client&nonce=gAp_KkNwy-x0iJ5N8Fxr66v6h0H3NtdkALO1WQ6A9gs

原因是当/oauth2/authorize访问oauth server时角色是anonymous，而根据oauth server的SecurityFilterChain中请求会先经过AnonymousAuthenticationFilter处理，之后进入ExceptionTranslationFilter（即出现异常或者401则跳转redirect到/login）再进入FilterSecurityInterceptor（这个filter会发现权限不足报AuthenticationException异常到上个filter，这个异常会被ExceptionTranslationFilter捕获）,具体实现：ExceptionTranslationFilter->catch ->DelegatingAuthenticationEntryPoint.commence(...)->LoginUrlAuthenticationEntryPoint.commence(...)即使用LoginUrlAuthenticationEntryPoint的默认重定向策略DefaultRedirectStrategy完成redirect到/login页面（即和自己定义的exceptionHandling里面LoginUrlAuthenticationEntryPoint相同原理），日志如下：

```xml
2022-05-29 15:29:23.090 DEBUG 11996 --- [nio-9001-exec-1] o.s.security.web.FilterChainProxy        : Securing GET /oauth2/authorize?response_type=code&client_id=login-client&scope=openid%20profile&state=-_hYJfo50QEI4oOgTqioPKARpSg8hNpblS8GGycu_po%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/login-client&nonce=1cm98p6I4fRtgYEtvTOgph38c-kGyXkCceQ_7_ZI0G0
2022-05-29 15:29:23.094 DEBUG 11996 --- [nio-9001-exec-1] s.s.w.c.SecurityContextPersistenceFilter : Set SecurityContextHolder to empty SecurityContext
2022-05-29 15:29:23.098 DEBUG 11996 --- [nio-9001-exec-1] org.apache.tomcat.util.http.Parameters   : Set encoding to UTF-8
2022-05-29 15:29:23.098 DEBUG 11996 --- [nio-9001-exec-1] org.apache.tomcat.util.http.Parameters   : Decoding query null UTF-8
2022-05-29 15:29:23.099 DEBUG 11996 --- [nio-9001-exec-1] org.apache.tomcat.util.http.Parameters   : Start processing with input [response_type=code&client_id=login-client&scope=openid%20profile&state=-_hYJfo50QEI4oOgTqioPKARpSg8hNpblS8GGycu_po%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/login-client&nonce=1cm98p6I4fRtgYEtvTOgph38c-kGyXkCceQ_7_ZI0G0]
2022-05-29 15:29:23.110 DEBUG 11996 --- [nio-9001-exec-1] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to anonymous SecurityContext
2022-05-29 15:29:23.111 DEBUG 11996 --- [nio-9001-exec-1] o.s.s.w.session.SessionManagementFilter  : Request requested invalid session id D2A49325F858222D3CCAAF990B244A05
2022-05-29 15:29:23.119 DEBUG 11996 --- [nio-9001-exec-1] o.s.s.w.a.i.FilterSecurityInterceptor    : Failed to authorize filter invocation [GET /oauth2/authorize?response_type=code&client_id=login-client&scope=openid%20profile&state=-_hYJfo50QEI4oOgTqioPKARpSg8hNpblS8GGycu_po%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/login-client&nonce=1cm98p6I4fRtgYEtvTOgph38c-kGyXkCceQ_7_ZI0G0] with attributes [authenticated]
2022-05-29 15:29:23.205 DEBUG 11996 --- [nio-9001-exec-1] o.s.s.w.s.HttpSessionRequestCache        : Saved request http://localhost:9001/oauth2/authorize?response_type=code&client_id=login-client&scope=openid%20profile&state=-_hYJfo50QEI4oOgTqioPKARpSg8hNpblS8GGycu_po%3D&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/login-client&nonce=1cm98p6I4fRtgYEtvTOgph38c-kGyXkCceQ_7_ZI0G0 to session
2022-05-29 15:29:23.205 DEBUG 11996 --- [nio-9001-exec-1] s.w.a.DelegatingAuthenticationEntryPoint : Trying to match using Or [Ant [pattern='/oauth2/token', POST], Ant [pattern='/oauth2/introspect', POST], Ant [pattern='/oauth2/revoke', POST]]
2022-05-29 15:29:23.205 DEBUG 11996 --- [nio-9001-exec-1] s.w.a.DelegatingAuthenticationEntryPoint : Trying to match using And [Not [RequestHeaderRequestMatcher [expectedHeaderName=X-Requested-With, expectedHeaderValue=XMLHttpRequest]], MediaTypeRequestMatcher [contentNegotiationStrategy=org.springframework.web.accept.HeaderContentNegotiationStrategy@73ccd549, matchingMediaTypes=[application/xhtml+xml, image/*, text/html, text/plain], useEquals=false, ignoredMediaTypes=[*/*]]]
2022-05-29 15:29:23.205 DEBUG 11996 --- [nio-9001-exec-1] s.w.a.DelegatingAuthenticationEntryPoint : Match found! Executing org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint@7b2bf745
2022-05-29 15:29:23.206 DEBUG 11996 --- [nio-9001-exec-1] o.s.s.web.DefaultRedirectStrategy        : Redirecting to http://localhost:9001/login
```

### 1.1 OAuth Server的SecurityFilterChain个数
必须的有至少1个SecurityFilterChain

```java
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.formLogin(Customizer.withDefaults()).build();
    }
```
可以自定义多个：
```java
    @Bean
    @Order(2)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return http.build();
    }
    
    @Bean
    @Order(3)
    public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
...
    }
```
定义多了一般没啥用，[官方推荐](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/getting-started.html)2个就够了，第一个是为了实现[Protocol Endpoints](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html) 第二个是为了自定义逻辑处理[authentication](https://docs.spring.io/spring-security/reference/servlet/authentication/index.html)， 我觉得非特殊情况一个SecurityFilterChain就够了,即第一个SecurityFilterChain非常关键在Spring Security OAuth Server中。

### 1.2 Protocol Endpoints的SecurityFilterChain链
#### 1.2.1 SecurityFilterChain运行原理
当有req来时代码调用FilterChainProxy.doFilter()->doFilterInternal()->inner class VirtualFilterChain.doFilter()->filter chain依次执行，代码如下

```java
@Override
		private static final class VirtualFilterChain implements FilterChain {
...
		@Override
		public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
			if (this.currentPosition == this.size) {
				if (logger.isDebugEnabled()) {
					logger.debug(LogMessage.of(() -> "Secured " + requestLine(this.firewalledRequest)));
				}
				// Deactivate path stripping as we exit the security filter chain
				this.firewalledRequest.reset();
				this.originalChain.doFilter(request, response);
				return;
			}
			this.currentPosition++;
			Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Invoking %s (%d/%d)", nextFilter.getClass().getSimpleName(),
						this.currentPosition, this.size));
			}
			nextFilter.doFilter(request, response, this);
		}

	}
```

#### 1.2.1 OAuth2AuthorizationServerConfigurer中注册的AuthenticationProvider列表
```xml
0 = {AnonymousAuthenticationProvider@8092} 
1 = {JwtClientAssertionAuthenticationProvider@8093} 
2 = {ClientSecretAuthenticationProvider@8094} 
3 = {PublicClientAuthenticationProvider@8095} 
4 = {OAuth2AuthorizationCodeRequestAuthenticationProvider@8096} 
5 = {OAuth2AuthorizationCodeAuthenticationProvider@8097} 
6 = {OAuth2RefreshTokenAuthenticationProvider@8098} 
7 = {OAuth2ClientCredentialsAuthenticationProvider@8099} 
8 = {OAuth2TokenIntrospectionAuthenticationProvider@8100} 
9 = {OAuth2TokenRevocationAuthenticationProvider@8101} 
10 = {OidcUserInfoAuthenticationProvider@8102} 
```

#### 1.2.2 OAuth Server运行时Filter列表
```xml
0 = {DisableEncodeUrlFilter@8051} 
1 = {WebAsyncManagerIntegrationFilter@6578} 
2 = {SecurityContextPersistenceFilter@8052} 
3 = {ProviderContextFilter@8053} 
4 = {HeaderWriterFilter@8054} 
5 = {CsrfFilter@8055} 
6 = {LogoutFilter@8056} 
7 = {OAuth2AuthorizationEndpointFilter@8057} 
8 = {OidcProviderConfigurationEndpointFilter@8058} 
9 = {NimbusJwkSetEndpointFilter@8059} 
10 = {OAuth2AuthorizationServerMetadataEndpointFilter@8060} 
11 = {OAuth2ClientAuthenticationFilter@8061} 
12 = {UsernamePasswordAuthenticationFilter@8062} 
13 = {DefaultLoginPageGeneratingFilter@8063} 
14 = {DefaultLogoutPageGeneratingFilter@8064} 
15 = {BearerTokenAuthenticationFilter@7188} 
16 = {RequestCacheAwareFilter@8065} 
17 = {SecurityContextHolderAwareRequestFilter@8066} 
18 = {AnonymousAuthenticationFilter@8067} 
19 = {SessionManagementFilter@8068} 
20 = {ExceptionTranslationFilter@8069} 
21 = {FilterSecurityInterceptor@7041} 
22 = {OAuth2TokenEndpointFilter@8070} 
23 = {OAuth2TokenIntrospectionEndpointFilter@8071} 
24 = {OAuth2TokenRevocationEndpointFilter@8072} 
25 = {OidcUserInfoEndpointFilter@8073} 
```

## 2.创建springboot-oauth2-resource-server服务

结构如下：
![在这里插入图片描述](./code_structure_1.png)
Controller代码：

```xml
@Controller
public class Oauth2ClientController {
  
  public static final Logger logger = LoggerFactory.getLogger(Oauth2ClientController.class);

  @GetMapping("/")
  public ResponseEntity<String> index() {
    return ResponseEntity.ok("my test");
  }
```
ResourceServerApplication启动类：

```xml
@SpringBootApplication
public class ResourceServerApplication {
	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}	
}
```
application.yml配置：

```xml
debug: true
server:
  port: 8080
spring:
  thymeleaf:
    cache: false
  security:
    oauth2:
      client:
        registration:
          login-client:
            provider: spring
            client-id: login-client
            client-secret: openid-connect
            client-authentication-method: client_secret_basic
            authorization-grant-type: authorization_code
            redirect-uri: http://127.0.0.1:8080/login/oauth2/code/login-client
            scope: openid,profile
            client-name: Spring
          google:
            client-id: your-app-client-id
            client-secret: your-app-client-secret
          github:
            client-id: xxxxxxxxxxxxxxxxx
            client-secret: xxxxxxxxxxxxxxxxxxxx
            redirect-uri: "{baseUrl}/login/oauth2/code/github"

        provider:
          spring:
            authorization-uri: http://localhost:9001/oauth2/authorize
            token-uri: http://localhost:9001/oauth2/token
            jwk-set-uri: http://localhost:9001/oauth2/jwks
            user-info-uri: http://localhost:9001/userinfo
            user-name-attribute: sub
  mvc:
    log-request-details: true
  level:
    org.springframework.web.client.RestTemplate: DEBUG
    
```
整体配置没太多的特殊地方，需要注意的是user-info-uri是/userinfo,而user-name-attribute可以是下面的字段，如sub.

```java
public interface IdTokenClaimNames {
    String ISS = "iss";
    String SUB = "sub";
    String AUD = "aud";
    String EXP = "exp";
    String IAT = "iat";
    String AUTH_TIME = "auth_time";
    String NONCE = "nonce";
    String ACR = "acr";
    String AMR = "amr";
    String AZP = "azp";
    String AT_HASH = "at_hash";
    String C_HASH = "c_hash";
}
```
## 3.创建springboot-oauth2-idp服务
这个服务主要是用来存user的信息，但是目前都是存到springboot-oauth2-server内存里面，所以这里可以暂时不用。后面有了再更新。

---

参考链接
[https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
[https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-userinfo.html#how-to-userinfo](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-userinfo.html#how-to-userinfo)
[https://github.com/spring-projects/spring-security-samples/blob/5.7.x/servlet](https://github.com/spring-projects/spring-security-samples/blob/5.7.x/servlet)
[https://openid.net/specs/openid-connect-core-1_0.html](https://openid.net/specs/openid-connect-core-1_0.html)
[https://datatracker.ietf.org/doc/html/rfc6749#section-4.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
