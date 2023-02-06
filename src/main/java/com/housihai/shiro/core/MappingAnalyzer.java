package com.housihai.shiro.core;

import java.lang.reflect.AnnotatedElement;

import com.housihai.shiro.core.domain.RequestMappingInfo;

/**
 * @author  reyco
 * @date    2022.11.30
 * @version v1.0.1
 *
 */
public interface MappingAnalyzer {

	/**
	 * 解析
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param element
	 * @param handlerType
	 * @return
	 */
	RequestMappingInfo analyzerRequestMappingInfo(AnnotatedElement element,Class<?> handlerType);

}
