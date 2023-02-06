package com.housihai.shiro.core.register;

import com.alibaba.fastjson.JSON;
import com.housihai.shiro.core.domain.RequestMappingInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.Map;
import java.util.Map.Entry;

/**
 * @author  reyco
 * @date    2022.11.23
 * @version v1.0.1
 */
public class ShiroRedisRegister{

	private Logger logger = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private RedisTemplate<String,String> redisTemplate;
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param applicationName
	 * @param requstMappingInfoMap
	 */
	public void register(String shiroRedisPrefix,String applicationName,Map<String,RequestMappingInfo> requstMappingInfoMap) {
		HashOperations<String, String, String> opsForHash = redisTemplate.opsForHash();
		for (Entry<String, RequestMappingInfo> enter : requstMappingInfoMap.entrySet()) {
			if(logger.isDebugEnabled()) {
				logger.debug("Register Permission: applicationName:"+applicationName+",path:"+enter.getKey()+",term:"+enter.getValue());
			}
			if(!opsForHash.hasKey(applicationName, enter.getKey())) {
				String key = (shiroRedisPrefix+":"+applicationName).replace("::", ":");
				opsForHash.put(key, enter.getKey(), JSON.toJSONString(enter.getValue()));
			}
		}
	}
}
