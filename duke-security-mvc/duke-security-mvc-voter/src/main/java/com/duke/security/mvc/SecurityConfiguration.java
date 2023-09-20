package com.duke.security.mvc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import java.util.Arrays;

//@Configuration
@EnableWebSecurity //@EnableWebSecurity注解将会启用Web安全功能，再继承WebSecurityConfigurerAdapter就代表这个配置类被Spring接管了
//@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//控制@Secured权限注解
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private JWTPasswordAuthenticationFilter authenticationFilter;

    @Autowired
    private AuthHandler authHandler;
    @Resource
    private CaptchaFilter captchaFilter;
    @Autowired
    private CustomSecurityMetadataSource metadataSource;

    private UrlAuthorizationConfigurer<HttpSecurity>.StandardInterceptUrlRegistry registry;

    /**
     * 跨域配置对象
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //配置允许访问的服务器域名
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        // AuthenticationManager目前属于工厂内部的类，需要用authenticationManagerBean方法把它暴露出来
        return super.authenticationManagerBean();
    }

    @Bean
    public JWTPasswordAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JWTPasswordAuthenticationFilter authenticationFilter = new JWTPasswordAuthenticationFilter();
        authenticationFilter.setAuthenticationManager(authenticationManager());
        this.authenticationFilter = authenticationFilter;
        return authenticationFilter;
    }

//    @Bean
//    PasswordEncoder passwordEncoder() {
////        return new CustomPasswordEncoder();
////        return new BCryptPasswordEncoder();
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    /**
     * 不注释掉会找不到bean AuthenticationManager
     * 配置Spring Security的Filter链
     @Override public void configure(WebSecurity web) {
     //        web.ignoring().antMatchers(WHITEURL);
     }
     */
    /**
     * 配置user-detail服务
     *
     @Override public void configure(AuthenticationManagerBuilder auth) throws Exception {
     }
     */
    /**
     * 配置如何通过拦截器保护请求
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        registry = http.apply(new UrlAuthorizationConfigurer<>(context)).getRegistry();
        registry.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
            @Override
            public <T extends FilterSecurityInterceptor> T postProcess(T object) {
                object.setSecurityMetadataSource(metadataSource);
                // rejectPublicInvocations默认为false，表示当getAttributes方法返回null时，允许访问受保护对象
                object.setRejectPublicInvocations(true);
                object.setAccessDecisionManager(affirmativeBased());
                return object;
            }
        });

        http.formLogin().disable();
        http.headers().frameOptions().disable();
        //关闭CSRF防御
        http.csrf().disable();
        //关掉 Security 自带的login
        http.httpBasic().disable();
        http.cors().configurationSource(corsConfigurationSource());
        http.headers().cacheControl();
        //关闭session会知管理,由Jwt来获取用户状态,否则即使token无效,也会有session信息,依旧判断用户为登录状态
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests().antMatchers("/auth/login", "/auth/captcha.jpg").permitAll().anyRequest().authenticated();

        http.logout().logoutSuccessHandler(authHandler);

        //配置回调接口
        http.exceptionHandling()
                //登录后,访问没有权限处理类
                .accessDeniedHandler(authHandler)
                //匿名访问,没有登录就请求其他接口就会回调 commence 提示没有请先登录在访问
                .authenticationEntryPoint(authHandler);
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                //使用jwt的Authentication,来解析过来的请求是否有token
                .addFilter(new JWTTokenAuthorizationFilter(authenticationManager()));

        authenticationFilter.setAuthenticationSuccessHandler(authHandler);
        authenticationFilter.setAuthenticationFailureHandler(authHandler);

        http.addFilterBefore(captchaFilter, UsernamePasswordAuthenticationFilter.class);

//        //配置登录,检测到用户未登录时跳转的url地址,登录放行
//        http.formLogin()
//                //需要跟前端表单的action地址一致
//                .loginProcessingUrl("/login")
//               // successHandler写在这里会导致登录成功后重定向，需要写在CustomUsernamePasswordAuthentication中
////                .successHandler(authenticationSuccessHandler)
////                .failureHandler(authenticationFailureHandler)
//                .permitAll();
    }

    @Bean
    public URLVoter urlVoter() {
        return new URLVoter();
    }

    /**
     * 下面这个Bean定义会造成循环依赖securityConfiguration -> JWTPasswordAuthenticationFilter
     *
     * @return
     */
    @Bean
    public AffirmativeBased affirmativeBased() {
        return new AffirmativeBased(Arrays.asList(new WebExpressionVoter(), new RoleVoter(), new AuthenticatedVoter(), urlVoter()));
    }
}