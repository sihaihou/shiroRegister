package com.housihai.shiro.core.properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * @author  reyco
 * @date    2022.11.30
 * @version v1.0.1
 */
@ConfigurationProperties(prefix = ShiroRedisProperties.SHIRO_REDIS_PREFIX)
public class ShiroRedisProperties {

	public final static String SHIRO_REDIS_PREFIX = "spring.shiro";

	@Value("${spring.cloud.nacos.discovery.service:${spring.application.name:}}")
	private String applicationName;

	private String serviceName = applicationName;

	private String shiroRedisPrefix = "service:shiro:permissions:";

	public String getServiceName() {
		if(StringUtils.isEmpty(serviceName)) {
			return applicationName;
		}
		return serviceName;
	}
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}
	public String getShiroRedisPrefix() {
		return shiroRedisPrefix;
	}
	public void setShiroRedisPrefix(String shiroRedisPrefix) {
		this.shiroRedisPrefix = shiroRedisPrefix;
	}
	public String getApplicationName() {
		return applicationName;
	}
	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}
}
