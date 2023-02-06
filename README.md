# shiroRegister

### 微服务Shiro权限注册


# 一:快速使用

### 1,Shiro配置
<pre>
/**
 * 
 * @author  reyco
 * @date    2022.12.02
 * @version v1.0.1
 */
@Configuration
public class ShiroConfig {

    @Bean("sessionManager")
    public DefaultSessionManager sessionManager() {
    	DefaultSessionManager sessionManager = new DefaultSessionManager();
        sessionManager.setSessionValidationSchedulerEnabled(true);
        //尽量和token的有效时间设置一致
        sessionManager.setGlobalSessionTimeout(1000*60*30);
        return sessionManager;
    }
	
    @Bean("securityManager")
    public SecurityManager securityManager(AuthRealm shiroRealm,SessionManager sessionManager) {
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(shiroRealm);
        securityManager.setSessionManager(sessionManager);
        return securityManager;
    }
    
  @Bean("authorizeFilter")
	public AuthorizeFilter authorizeFilter(DefaultSecurityManager securityManager,ShiroService shiroService) {
		 AuthorizeFilter authorizeFilter = new AuthorizeFilter();
		 authorizeFilter.setSecurityManager(securityManager);
		 authorizeFilter.setShiroService(shiroService);
		 Set<String> exclude = new HashSet<>();
		 exclude.add("/provider1/login");
		 exclude.add("/provider1/test/**");
		 authorizeFilter.setExclude(exclude);
		 authorizeFilter.setOrder(3);
		 return authorizeFilter;
	}
}
</pre>

### 2,AuthRealm
<pre>
/**
 * 
 * @author  reyco
 * @date    2022.11.24
 * @version v1.0.1
 */
@Component
public class AuthRealm extends AuthorizingRealm {

    @Autowired
    ShiroServiceImpl shiroService;

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof AuthToken;
    }

    /**
     * @Author Mr.Wang
     * @Description shiro授权
     * @Date 1:53 下午 2021/12/24
     * @Param
     **/
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    	 Account account = (Account) principals.getPrimaryPrincipal();
         // 用户权限列表
         Set<String> permsSet = shiroService.getUserPermissions(account.getId());
         SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
         info.setStringPermissions(permsSet);
         return info;
    }

    /**
     * @Author Mr.Wang
     * @Description shiro认证
     * @Date 1:54 下午 2021/12/24
     * @Param
     **/
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String accountTokenJson = token.getPrincipal().toString();
        //根据token查询对应用户信息
        AccountToken accountToken = shiroService.getToken(accountTokenJson);
        if (accountToken == null) {
            throw new IncorrectCredentialsException("Token验证过期，请重新登陆！");
        }
        //获取用户信验证用户账号是否为正常状态
        Account account = shiroService.getUser(accountToken.getId());
       
        //验证用户是否存在并且账号是否为锁定状态
        if (account == null) {
            throw new IncorrectCredentialsException("您的账号已经被锁定，请联系管理员解封后重新尝试！");
        }
        //get userInfo
        SimpleAuthenticationInfo authenticationInfo = null;
        if (account != null) {
            authenticationInfo = new SimpleAuthenticationInfo(account, accountTokenJson, this.getName());
        }
        return authenticationInfo;
    }
}
/**
 * @author reyco
 * @date 2022.11.24
 * @version v1.0.1
 */
@Service
public class ShiroServiceImpl implements ShiroService{
	
	@Autowired
	private RedisTemplate<String, String> redisTemplate;
	
	@Autowired
	private UserService userService;
	
	public static final String SERVICE_SHIRO_PERMISSIONS = "service:shiro:permissions:";
	
	public static Map<Long,List<String>> perms = new HashMap<Long,List<String>>(){
		{
			put(1L,Arrays.asList("user:info","user:list","user:delete","user:add")); 
			put(2L,Arrays.asList("user:info","user:list","user:delete","user:add")); 
			put(3L,Arrays.asList("user:info","user:list","user:add")); 
			put(4L,Arrays.asList("user:info","user:list")); 
			put(5L,Arrays.asList("user:info")); 
		}
	};
	
	
	public Set<String> getUserPermissions(Long id){
		return new HashSet<>(perms.get(id));
	}
	public AccountToken getToken(String token) {
		String accountTokenJson = redisTemplate.opsForValue().get("login:token:" + token);
		AccountToken accountToken = JsonUtils.jsonToObj(accountTokenJson, AccountToken.class);
		return accountToken;
	}

	public Account getUser(Long userId) {
		return userService.get(userId);
	}
	public PermissionInfo getPermission(String service,String path) {
		HashOperations<String, String, String> opsForHash = redisTemplate.opsForHash();
		String requestMappingInfoJson = opsForHash.get(SERVICE_SHIRO_PERMISSIONS+service, path);
		RequestMappingInfo requestMappingInfo = JsonUtils.jsonToObj(requestMappingInfoJson, RequestMappingInfo.class);
		if(requestMappingInfo==null || requestMappingInfo.getPermissionInfo()==null) {
			return null;
		}
		return requestMappingInfo.getPermissionInfo();
	}
	@Override
	public boolean isEnable() throws RuntimeException {
		return true;
	}
	@Override
	public List<RequestMappingInfo> getRequestMappingInfos(String service) throws RuntimeException {
		HashOperations<String, String, String> opsForHash = redisTemplate.opsForHash();
		List<String> requestMappingInfosJson = opsForHash.values(SERVICE_SHIRO_PERMISSIONS+service);
		List<RequestMappingInfo> res = new ArrayList<>();
		if(CollectionUtils.isNotEmpty(requestMappingInfosJson)) {
			requestMappingInfosJson.stream().forEach(requestMappingInfoStr->{
				RequestMappingInfo requestMappingInfo = JsonUtils.jsonToObj(requestMappingInfoStr, RequestMappingInfo.class);
				res.add(requestMappingInfo);
			});
		}
		return res;
	}
}
</pre>


### 3,gateway,GlobalFilter
<pre>
/** 
 * @author  reyco
 * @date    2022.11.22
 * @version v1.0.1 
 */
public class AuthorizeFilter implements GlobalFilter,Ordered {

	private static final Logger log= LoggerFactory.getLogger(AuthorizeFilter.class);
	
	private PathMatcher pathMatcher = new AntPathMatcher();
	// 拦截器处理类
	private AuthorizingHandlerInterceptor authorizingHandlerInterceptor;
	// 通过ShiroConfig设置
	private Set<String> exclude;	
	private DefaultSecurityManager securityManager;
	// 获取路径权限和TOKEN的值
	private ShiroService shiroService;
	
	private final Map<String,PermissionInfo> pathPermissionInfoCache = new ConcurrentHashMap<String,PermissionInfo>();
	
	private final Map<String, SearchPermissionInfo> searchPermissionInfoMap = new ConcurrentHashMap<String, SearchPermissionInfo>();
	
	private static final long DEFAULT_HEART_BEAT_INTERVAL = TimeUnit.SECONDS.toMillis(15);
	
	private ScheduledExecutorService executorService;
	
	/**
	 * Order must be greater than or equal to 3
	 */
	private int order = 3;
	/**
	 * 构建需要排除地址Map与及 拦截器处理管理类
	 */
	public AuthorizeFilter() {
		this.exclude = new HashSet<String>();
		if(authorizingHandlerInterceptor==null) {
			authorizingHandlerInterceptor = new AuthorizingHandlerInterceptor();
		}
		executorService = new ScheduledThreadPoolExecutor(Runtime.getRuntime().availableProcessors()*2+1, new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setDaemon(true);
                thread.setName("com.vanmilk.shiro.redis.searchPermissionTask");
                return thread;
            }
        });
	}
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpResponse response = exchange.getResponse();
		ServerHttpRequest request = exchange.getRequest();
		// 排除地址
		if(isExclude(exchange)) {
			return chain.filter(exchange);
		}
		// 校验token有效性
		if(!isLogin(exchange) || shiroService.getToken(request.getHeaders().getFirst(shiroService.getTokenName()))==null ) {
			response.setStatusCode(HttpStatus.UNAUTHORIZED);
		    	Map<String, Object> map = new HashMap<>();
		    	map.put("msg", "未登录");
		    	map.put("code", "Not login");
				log.debug("Gateway Call failed-Not login！接口:{}",exchange.getRequest().getPath());
		    	byte[] bytes = JSON.toJSONString(map).getBytes(StandardCharsets.UTF_8);
		    	DataBuffer buffer = response.bufferFactory().wrap(bytes);
		    	return response.writeWith(Mono.just(buffer));
		}
		if(!shiroService.isEnable()) {
			return chain.filter(exchange);
		}
		// 校验当前是否有请求地址权限
		if(isPermission(exchange)) {
			log.debug("Authentication succeeded！接口:{}",exchange.getRequest().getPath());
			return chain.filter(exchange);
		}
    	response.setStatusCode(HttpStatus.NON_AUTHORITATIVE_INFORMATION);
    	Map<String, Object> map = new HashMap<>();
    	map.put("msg", "没有权限");
    	map.put("code", "No Permission");
		log.debug("Gateway Call failed-No Permission！接口:{}",exchange.getRequest().getPath());
    	DataBuffer buffer = response.bufferFactory().wrap(JSON.toJSONString(map).getBytes(StandardCharsets.UTF_8));
    	return response.writeWith(Mono.just(buffer));
	}
	/**
	 * 
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1 
	 * @param exchange
	 * @return
	 * 完成shiro subject.login 然后校验当前用户是否有请求地址的权限
	 */
	private boolean isPermission(ServerWebExchange exchange) {
		Route route = exchange.getAttribute(GATEWAY_ROUTE_ATTR);
		String service = route.getUri().getHost();
		IAccountToken accountToken;
		String token;
		// PermissionInfo 请求路径配置的权限标识
		PermissionInfo permissionInfo;
		ServerHttpRequest request = exchange.getRequest();
		// 获取请求路径（截取掉前缀）
		String path = request.getPath().value();

		// token有效并且是admin账号或者该路径没有配置权限注解，则返回有权限
		if(((accountToken=shiroService.getToken(token=request.getHeaders().getFirst(shiroService.getTokenName())))!=null && accountToken.getId().equals(1L)) 
						|| (permissionInfo=getPermissionInfo(service,path))==null) {
					return true;
		}

		// 完成subject.login
		SecurityUtils.setSecurityManager(securityManager);
		Subject subject = SecurityUtils.getSubject();
		subject.login(new AuthToken(token));
		// 进行拦截器进行处理
		return authorizingHandlerInterceptor.invoke(subject, permissionInfo);
	}
	/**
	 * 获取权限
	 * @author  reyco
	 * @date    2022年12月14日
	 * @version v1.0.1 
	 * @param serviceName 服务名
	 * @param path 路径
	 * @return 
	 */
	private PermissionInfo getPermissionInfo(String serviceName,String path) {
		PermissionInfo permissionInfo = pathPermissionInfoCache.get(path);
		if(permissionInfo!=null) {
			return permissionInfo;
		}
		permissionInfo = shiroService.getPermission(serviceName,path);
		if(permissionInfo==null) {
			permissionInfo = new PermissionInfo();
		}
		pathPermissionInfoCache.put(path, permissionInfo);
		SearchPermissionInfo searchPermissionInfo = new SearchPermissionInfo();
		searchPermissionInfo.setServiceName(serviceName);
		searchPermissionInfo.setPeriod(DEFAULT_HEART_BEAT_INTERVAL);
		//添加 
		addSearchPermissionInfo(serviceName, searchPermissionInfo);
		return permissionInfo;
	}
	/**
	 * 添加
	 * @author  reyco
	 * @date    2022年12月14日
	 * @version v1.0.1 
	 * @param serviceName
	 * @param searchPermissionInfo
	 */
	public void addSearchPermissionInfo(String serviceName, SearchPermissionInfo searchPermissionInfo){
		SearchPermissionInfo existBeat;
		if((existBeat=searchPermissionInfoMap.remove(serviceName))!=null) {
			existBeat.setStopped(true);
		}
		searchPermissionInfoMap.put(serviceName, searchPermissionInfo);
		executorService.schedule(new SearchPermissionTask(searchPermissionInfo), searchPermissionInfo.getPeriod(), TimeUnit.MILLISECONDS);
	}
	/**
	 * 
	 * @author  reyco
	 * @date    2022.12.14
	 * @version v1.0.1
	 */
	class SearchPermissionTask implements Runnable{
		
		private SearchPermissionInfo searchPermissionInfo;
		
		public SearchPermissionTask(SearchPermissionInfo searchPermissionInfo) {
			super();
			this.searchPermissionInfo = searchPermissionInfo;
		}
		@Override
		public void run() {
			if(searchPermissionInfo.isStopped()) {
				return;
			}
			Long period = searchPermissionInfo.getPeriod();
			try {
				if(log.isDebugEnabled()) {
					log.debug("【权限同步】 权限同步开始: {}",JsonUtils.objToJson(searchPermissionInfo));
				}
				List<RequestMappingInfo> requestMappingInfos = shiroService.getRequestMappingInfos(searchPermissionInfo.getServiceName());
				if(CollectionUtils.isNotEmpty(requestMappingInfos)) {
					requestMappingInfos.stream().forEach(requestMappingInfo->{
						pathPermissionInfoCache.put(requestMappingInfo.getPaths()[0], requestMappingInfo.getPermissionInfo());
					});
				}
				if(log.isDebugEnabled()) {
					log.debug("【权限同步】 权限同步结束: {}",JsonUtils.objToJson(searchPermissionInfo));
				}
			} catch (Exception e) {
				log.error("【权限同步】 权限同步失败: {}, msg: {}",JsonUtils.objToJson(searchPermissionInfo), e.getMessage());
			}
			executorService.schedule(new SearchPermissionTask(searchPermissionInfo), period, TimeUnit.MILLISECONDS);
		}
	}
	static class SearchPermissionInfo{
		private String serviceName;
		private volatile boolean stopped;
		private Long period;
		public String getServiceName() {
			return serviceName;
		}
		public void setServiceName(String serviceName) {
			this.serviceName = serviceName;
		}
		public boolean isStopped() {
			return stopped;
		}
		public void setStopped(boolean stopped) {
			this.stopped = stopped;
		}
		public Long getPeriod() {
			return period;
		}
		public void setPeriod(Long period) {
			this.period = period;
		}
	}
	/**
	 * 
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1 
	 * @param exchange
	 * @return
	 */
	private boolean isExclude(ServerWebExchange exchange) {
		Object originalPathObj = exchange.getAttribute(OriginalPathFilter.ORIGINAL_PATH);
		String originalPath = "";
		if(originalPathObj!=null) {
			originalPath = originalPathObj.toString();
		}
		for (String path : exclude) {
			if(pathMatcher.match(path,originalPath)) {
				return true;
			}
		}
		return false;
	}
	/**
	 * 
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1 
	 * @param exchange
	 * @return
	 * 校验token有效性
	 */
	private boolean isLogin(ServerWebExchange exchange) {
		if(StringUtils.isBlank(exchange.getRequest().getHeaders().getFirst(shiroService.getTokenName()))) {
			return false;
		}
		return true;
	}
	/**
	 * @param authorizingHandlerInterceptor the authorizingHandlerInterceptor to set
	 */
	public void setAuthorizingHandlerInterceptor(AuthorizingHandlerInterceptor authorizingHandlerInterceptor) {
		this.authorizingHandlerInterceptor = authorizingHandlerInterceptor;
	}
	/**
	 * @return the authorizingHandlerInterceptor
	 */
	public AuthorizingHandlerInterceptor getAuthorizingHandlerInterceptor() {
		return authorizingHandlerInterceptor;
	}
	/**
	 * @param pathMatcher the pathMatcher to set
	 */
	public void setPathMatcher(PathMatcher pathMatcher) {
		this.pathMatcher = pathMatcher;
	}
	/**
	 * @return the pathMatcher
	 */
	public PathMatcher getPathMatcher() {
		return pathMatcher;
	}
	/**
	 * @param exclude the exclude to set
	 */
	public void setExclude(Set<String> exclude) {
		this.exclude = exclude;
	}
	/**
	 * @return the exclude
	 */
	public Set<String> getExclude() {
		return exclude;
	}
	/**
	 * @param securityManager the securityManager to set
	 */
	public void setSecurityManager(DefaultSecurityManager securityManager) {
		this.securityManager = securityManager;
	}
	/**
	 * @return the securityManager
	 */
	public SecurityManager getSecurityManager() {
		return securityManager;
	}
	/**
	 * @param shiroService the shiroService to set
	 */
	public void setShiroService(ShiroService shiroService) {
		this.shiroService = shiroService;
	}
	/**
	 * @return the shiroService
	 */
	public ShiroService getShiroService() {
		return shiroService;
	}
	@Override
	public int getOrder() {
		return order;
	}
	public void setOrder(int order) {
		this.order = order;
	}
}
</pre>
<pre>
  /** 
 * @author  reyco
 * @date    2022.12.14
 * @version v1.0.1 
 */
public class OriginalPathFilter implements GlobalFilter,Ordered{
	
	public static final String ORIGINAL_PATH = "originalPath";
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		Map<String, Object> attributes = exchange.getAttributes();
		attributes.put(ORIGINAL_PATH, exchange.getRequest().getPath());
		return chain.filter(exchange);
	}
	
	@Override
	public int getOrder() {
		return 0;
	}
}
</pre>

### 4,授权处理拦截器
<pre>
/** 
 * 授权拦截器处理管理类
 * @author  reyco
 * @date    2022.11.30
 * @version v1.0.1 
 */
public class AuthorizingHandlerInterceptor{
	// 拦截器列表
	private List<AuthorizingHandler> authorizingHandlers;
	/**
	 * @param authorizingHandlers the authorizingHandlers to set
	 */
	public void setAuthorizingHandlers(List<AuthorizingHandler> authorizingHandlers) {
		this.authorizingHandlers = authorizingHandlers;
	}
	/**
	 * @return the authorizingHandlers
	 */
	public List<AuthorizingHandler> getAuthorizingHandlers() {
		return authorizingHandlers;
	}
	/** 
   * 校验当前主体是否有请求路径权限
	 * @author  reyco
	 * @date    2022年12月2日
	 * @version v1.0.1  
	 */
	public boolean invoke(Subject subject, PermissionInfo permissionInfo) throws AuthorizationException {
		AuthorizingHandler authorizingHandler = getMatchAuthorizingHandler(permissionInfo);
		if(authorizingHandler==null) {
			return true;
		}
		return authorizingHandler.assertAuthorized(subject, permissionInfo);
	}
	/**
	 * 管理拦截器处理类
	 */
	public AuthorizingHandlerInterceptor() {
		List<AuthorizingHandler> authorizingHandlers = new ArrayList<AuthorizingHandler>();
		authorizingHandlers.add(new PermissionAuthorizingHandler());
		authorizingHandlers.add(new RoleAuthorizingHandler());
		setAuthorizingHandlers(authorizingHandlers);
	}
	protected AuthorizingHandler getMatchAuthorizingHandler(PermissionInfo permissionInfo) {
		List<AuthorizingHandler> authorizingHandlers = getAuthorizingHandlers();
		for (AuthorizingHandler authorizingHandler : authorizingHandlers) {
			if(authorizingHandler.support(permissionInfo)) {
				return authorizingHandler;
			}
		}
		return null;
	}
}
</pre>

### 5,授权处理器接口
<pre>
/** 
 * 授权Handler接口
 * @author  reyco
 * @date    2022.11.30
 * @version v1.0.1 
 */
public interface AuthorizingHandler {
	
	// 支持的权限 permissions 或 roles
	boolean support(PermissionInfo permissionInfo);
	
	// 当前登录主体是否有权限
	boolean assertAuthorized(Subject subject, PermissionInfo permissionInfo) throws AuthorizationException;
	
}
</pre>
>### 5-1,权限校验处理类
<pre>
/**
 * 权限校验处理类
 * @author reyco
 * @date 2022.11.30
 * @version v1.0.1
 */
public class PermissionAuthorizingHandler implements AuthorizingHandler{
	
	@Override
	public boolean support(PermissionInfo permissionInfo) {
		return permissionInfo.getPermissions()!=null;
	}
	/**
	 * 
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1 
	 * @param subject
	 * @param permissionInfo
	 * @return
	 * @throws AuthorizationException
	 */
	@Override
	public boolean assertAuthorized(Subject subject, PermissionInfo permissionInfo) throws AuthorizationException {
		String[] perms = permissionInfo.getPermissions();
		if(perms==null || perms.length == 0 ) {
			return true;
		}
		if (perms.length == 1 && subject.isPermitted(perms[0])) {
			return true;
		}
		if (Logical.AND.equals(permissionInfo.getLogical()) && subject.isPermittedAll(perms)) {
			return true;
		}
		if (Logical.OR.equals(permissionInfo.getLogical())) {
			for (String permission : perms) {
				if (subject.isPermitted(permission)) {
					return true;
				}
			}
		}
		return false;
	}
}
</pre>
>### 5-2,角色校验处理类
<pre>
/**
 * 角色校验处理类
 * @author reyco
 * @date 2022.11.30
 * @version v1.0.1
 */
public class RoleAuthorizingHandler implements AuthorizingHandler {

	@Override
	public boolean support(PermissionInfo permissionInfo) {
		return permissionInfo.getRoles() != null;
	}

	@Override
	public boolean assertAuthorized(Subject subject, PermissionInfo permissionInfo) throws AuthorizationException {
		String[] roles = permissionInfo.getRoles();
		if(roles==null || roles.length == 0 ) {
			return true;
		}
		if (roles.length == 1 && subject.hasRole(roles[0])) {
			return true;
		}
		if (Logical.AND.equals(permissionInfo.getLogical()) && subject.hasAllRoles(Arrays.asList(roles))) {
			return true;
		}
		if (Logical.OR.equals(permissionInfo.getLogical())) {
			for (String role : roles) {
				if (subject.hasRole(role)) {
					return true;
				}
			}
		}
		return false;
	}
}
</pre>

