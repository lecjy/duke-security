package com.duke.security.reactive;

import com.duke.common.base.utils.CollectionUtils;
import com.duke.security.common.sys.resource.Resource;
import com.duke.security.common.sys.resource.ResourceService;
import com.duke.security.common.sys.user.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.WebSessionManager;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;

@EnableWebFluxSecurity// 要在Spring Security 5中启用WebFlux支持，只需要指定@EnableWebFluxSecurity注释
@EnableReactiveMethodSecurity//启用@PreAuthorize注解配置，如果不加这个注解的话，即使方法中加了@PreAuthorize也不会生效
@Configuration
public class ReactiveSecurityConfiguration {

    @Autowired
    private ReactiveAuthHandler reactiveAuthHandler;
    @Autowired
    private ResourceService resourceService;

    private AntPathMatcher antMatcher = new AntPathMatcher();

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //配置允许访问的服务器域名
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.addAllowedOriginPattern("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Sebflux没有WebSecurityConfigurerAdapter对应的配置类，默认的ServerWebExchange的实现类DefaultServerWebExchange中有关于session的配置，
     * 基于此可以在系统中注入一个DefaultWebSessionManager，并调用setSessionIdResolver方法，设置的SessionIdResolver为CookieWebSessionIdResolver的子类，置空session过期的方法expireSession
     * 相当于session过期之后不做任何处理，因此也不会有set-cookie的响应
     */
    @Bean
    public WebSessionManager webSessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionIdResolver(new CookieWebSessionIdResolver() {
            @Override
            public void expireSession(ServerWebExchange exchange) {
                //session 过期不做任何处理
            }
        });
        return sessionManager;
    }

    @Bean
    SecurityWebFilterChain reactiveSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http.formLogin().disable();
        http.headers().frameOptions().disable();
        //关闭CSRF防御
        http.csrf().disable();
        //关掉 Security 自带的login
        http.httpBasic().disable();
        http.cors().configurationSource(corsConfigurationSource());
//        http.headers().cacheControl();
        //关闭session会知管理,由Jwt来获取用户状态,否则即使token无效,也会有session信息,依旧判断用户为登录状态
//        http.webSessionServerSecurityContextRepository().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeExchange().pathMatchers("/auth/login", "/auth/captcha.jpg").permitAll().anyExchange().access(reactiveAuthorizationManager());
        http.logout().logoutSuccessHandler(reactiveAuthHandler);

        //配置回调接口
        http.exceptionHandling()
                //登录后,访问没有权限处理类
                .accessDeniedHandler(reactiveAuthHandler)
                //匿名访问,没有登录就请求其他接口就会回调 commence 提示没有请先登录在访问
                .authenticationEntryPoint(reactiveAuthHandler);
        http.addFilterAt(new ReactiveJWTTokenAuthorizationFilter(), SecurityWebFiltersOrder.HTTP_BASIC);
        return http.build();
    }

    // 如果不添加任何额外的配置，不管发送任何请求，都会跳到spring security提供的默认登陆页面，可以自定义的登陆页面
//    @Bean
//    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
//        RedirectServerAuthenticationEntryPoint loginPoint = new RedirectServerAuthenticationEntryPoint("/xinyue-server-a/account/index");
//        http.authorizeExchange().pathMatchers("/xinyue-server-a/easyui/**","/xinyue-server-a/js/**","/xinyue-server-a/account/index","/xinyue-server-a/account/login").permitAll()
//                .and().formLogin().loginPage("/xinyue-server-a/account/authen").authenticationEntryPoint(loginPoint)
//                .and().authorizeExchange().anyExchange().authenticated()
//                .and().csrf().disable();
//        return http.build();
//    }

    @Bean
    public ReactiveAuthorizationManager<AuthorizationContext> reactiveAuthorizationManager() {
        return (authentication, exchange) -> authentication.map(item -> {
            User user = (User) item.getPrincipal();
            // TODO 查询数据库判断是否用权限
            List<Resource> resources = resourceService.queryResourcesByRoleId(user.getRoleId());
            if (CollectionUtils.isEmpty(resources)) {
                return false;
            }
            List<Resource> matchedResources = resources.stream().filter(resource -> match(resource, exchange.getExchange().getRequest())).toList();
            return matchedResources != null && matchedResources.size() > 0;
        }).map(AuthorizationDecision::new).defaultIfEmpty(new AuthorizationDecision(false));
    }

//    @Override
//    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext object) {
//        ServerHttpRequest request = object.getExchange().getRequest();
//        String requestUrl = request.getPath().pathWithinApplication().value();
//        // TODO 查询数据库判断是否用权限
//        List<Resource> list = Arrays.asList(Resource.builder().path("/auth").build());
//        if (org.springframework.util.CollectionUtils.isEmpty(list)) {
//            return Mono.just(new AuthorizationDecision(false));
//        }
//        return authentication
//                .filter(a -> a.isAuthenticated())
//                .flatMapIterable(a -> a.getAuthorities())
//                .map(g -> g.getAuthority())
//                .any(c -> {
//                    return true;
//                })
//                .map(hasAuthority -> new AuthorizationDecision(hasAuthority))
//                .defaultIfEmpty(new AuthorizationDecision(false));
//    }

    private boolean match(Resource resource, ServerHttpRequest request) {
        boolean pathMatch = Arrays.stream(resource.getPathes().split(",")).anyMatch(path -> antMatcher.match(path, request.getURI().getPath()));
        boolean methodMatch = Arrays.stream(resource.getMethodes().split(",")).anyMatch(item -> request.getMethod().matches(item));
        return pathMatch && methodMatch;
    }
}