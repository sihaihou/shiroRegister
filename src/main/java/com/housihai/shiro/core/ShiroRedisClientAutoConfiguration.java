package com.housihai.shiro.core;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.housihai.shiro.core.domain.RequestMappingInfo;
import com.housihai.shiro.core.properties.ShiroRedisProperties;
import com.housihai.shiro.core.register.ShiroRedisRegister;

/**
 * @author reyco
 * @date 2022.11.23
 * @version v1.0.1
 */
@ConditionalOnClass(RedisTemplate.class)
@EnableConfigurationProperties(ShiroRedisProperties.class)
public class ShiroRedisClientAutoConfiguration implements BeanPostProcessor{

	protected Logger logger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private ShiroRedisRegister shiroRedisRegister;

	@Autowired
	private ShiroRedisProperties shiroRedisProperties;

	private MappingAnalyzer mappingAnalyzer = new DefaultMappingAnalyzer();

	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		registerHandlerMethods(bean.getClass());
		return bean;
	}
	/**
	 *
	 * @author reyco
	 * @date 2022年11月30日
	 * @version v1.0.1
	 * @param bean
	 * @return
	 * @throws BeansException
	 */
	private void registerHandlerMethods(Class<?> beanClass) throws BeansException {
		Map<String, RequestMappingInfo> requstMappingInfoMap = null;
		try {
			requstMappingInfoMap = builderRequestMappingShiroInfo(beanClass);
			if (requstMappingInfoMap != null) {
				try {
					if(logger.isDebugEnabled()) {
						logger.debug("Handler:" + beanClass + ",Start to register Shiro Permissions");
					}
					String service = shiroRedisProperties.getServiceName();
					shiroRedisRegister.register(shiroRedisProperties.getShiroRedisPrefix(),service,requstMappingInfoMap);
				} catch (Exception e) {
					logger.error("Handler:" + beanClass + ",Failed to register Shiro Permissions");
				}finally {
					if(logger.isDebugEnabled()) {
						logger.debug("Handler:" + beanClass + ",End of registering Shiro permissions");
					}
				}
			}
		} catch (Exception e) {
			logger.error(beanClass + ", Analyzer RequestMappingInfo failed");
		}
	}

	/**
	 *
	 * @author reyco
	 * @date 2022年11月30日
	 * @version v1.0.1
	 * @param bean
	 * @return
	 * @throws Exception
	 */
	private Map<String, RequestMappingInfo> builderRequestMappingShiroInfo(Class<?> beanClass) throws Exception {
		if (!isHandler(beanClass)) {
			return null;
		}
		Method[] methods = beanClass.getDeclaredMethods();
		Map<String, RequestMappingInfo> requstMappingInfoMap = new HashMap<String, RequestMappingInfo>();
		for (int i = 0; i < methods.length; i++) {
			Method method = methods[i];
			RequestMappingInfo requestMappingInfo = mappingAnalyzer.analyzerRequestMappingInfo(method, beanClass);
			if (requestMappingInfo == null) {
				continue;
			}
			requstMappingInfoMap.put(requestMappingInfo.getPaths()[0], requestMappingInfo);
		}
		return requstMappingInfoMap;
	}

	/**
	 * @author reyco
	 * @date 2022年11月30日
	 * @version v1.0.1
	 * @param beanType
	 * @return
	 */
	protected boolean isHandler(Class<?> beanType) {
		return (AnnotatedElementUtils.hasAnnotation(beanType, Controller.class)
				|| AnnotatedElementUtils.hasAnnotation(beanType, RequestMapping.class));
	}

	public MappingAnalyzer getMappingAnalyzer() {
		return mappingAnalyzer;
	}
	public void setMappingAnalyzer(MappingAnalyzer mappingAnalyzer) {
		this.mappingAnalyzer = mappingAnalyzer;
	}
	@Bean
	@ConditionalOnClass(RedisTemplate.class)
	public ShiroRedisRegister shiroRedisRegister() {
		return new ShiroRedisRegister();
	}
}
